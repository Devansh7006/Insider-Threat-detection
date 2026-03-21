"""Windows Endpoint Compliance Collector.

Checks basic security control configuration and periodically emits a
COMPLIANCE_STATUS event for high-level posture visibility.

Controls:
 - Firewall enabled
 - Disk encryption (BitLocker protection)
 - Screen lock timeout policy
 - Antivirus (Windows Defender) service running
 - USB storage policy (USBSTOR service disabled)

Registry / path references in this file are written with double backslashes
to avoid Python treating them as escape sequences, for example:
  HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR

Privacy: configuration-only, no user content or identifiers.
"""

import os
import subprocess
import time
from typing import Any, Dict, Optional, List


DEFAULT_INTERVAL_SEC = 300.0  # 5 minutes


def _run_command(cmd: List[str], timeout: float = 5.0) -> Optional[str]:
    """
    Run a command and return stdout as text, or None on any error.
    Never raises.
    """
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            shell=False,
        )
        if completed.returncode != 0:
            return None
        return completed.stdout or ""
    except Exception:
        return None


def _check_firewall_enabled() -> bool:
    """
    Check Windows Firewall status via netsh.
    Returns True if firewall is enabled in at least one profile.
    """
    if os.name != "nt":
        return False
    # netsh advfirewall show allprofiles
    output = _run_command(["netsh", "advfirewall", "show", "allprofiles"])
    if not output:
        return False
    try:
        for line in output.splitlines():
            line = line.strip().lower()
            if line.startswith("state") and "on" in line:
                return True
    except Exception:
        return False
    return False


def _check_disk_encryption() -> bool:
    """
    Check BitLocker protection status via manage-bde.
    Returns True if protection status is ON for any volume.
    """
    if os.name != "nt":
        return False
    # manage-bde -status
    output = _run_command(["manage-bde", "-status"])
    if not output:
        return False
    out_lower = output.lower()
    # Look for "protection status: protection on" or similar
    return "protection status:" in out_lower and "protection on" in out_lower


def _check_screen_lock_policy(max_timeout_sec: int = 600) -> bool:
    """Check screen saver timeout from the ScreenSaveTimeOut value.

    Registry path (for reference):
      HKCU\\Control Panel\\Desktop
    """
    if os.name != "nt":
        return False
    # reg query "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut
    output = _run_command(
        [
            "reg",
            "query",
            r"HKCU\Control Panel\Desktop",
            "/v",
            "ScreenSaveTimeOut",
        ]
    )
    if not output:
        return False
    try:
        for line in output.splitlines():
            if "ScreenSaveTimeOut" in line:
                parts = line.split()
                if not parts:
                    continue
                # value is usually the last token
                raw_val = parts[-1]
                timeout = int(raw_val)
                if timeout <= 0:
                    return False
                return timeout <= max_timeout_sec
    except Exception:
        return False
    return False


def _check_antivirus_running() -> bool:
    """
    Check if Windows Defender (WinDefend) service is running.
    Uses 'sc query WinDefend' and looks for RUNNING state.
    """
    if os.name != "nt":
        return False
    output = _run_command(["sc", "query", "WinDefend"])
    if not output:
        return False
    try:
        for line in output.splitlines():
            line_lower = line.strip().lower()
            if line_lower.startswith("state"):
                # Example: STATE              : 4  RUNNING
                if "running" in line_lower:
                    return True
    except Exception:
        return False
    return False


def _check_usb_restricted() -> bool:
    """Check USB storage policy via the USBSTOR service Start value.

    Registry path (for reference only, not used as a Python string literal):
      HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR

    Returns True if Start == 4 (USB disabled/restricted).
    """
    if os.name != "nt":
        return False
    output = _run_command(
        [
            "reg",
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
            "/v",
            "Start",
        ]
    )
    if not output:
        return False
    try:
        for line in output.splitlines():
            if "Start" in line:
                parts = line.split()
                if not parts:
                    continue
                raw_val = parts[-1]
                # Value is typically shown as a decimal or hex integer.
                # Try decimal first, then hex (0x...).
                try:
                    val = int(raw_val, 0)
                except ValueError:
                    continue
                return val == 4
    except Exception:
        return False
    return False


def _enforce_firewall() -> None:
    """Enable Windows Firewall for all profiles."""
    if os.name != "nt":
        return
    try:
        print("[COMPLIANCE] Firewall disabled \u2192 enforcing")
        _run_command(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
    except Exception:
        print("[COMPLIANCE] enforcement failed")


def _enforce_screen_lock() -> None:
    """Set ScreenSaveTimeOut to 600 seconds (10 minutes)."""
    if os.name != "nt":
        return
    try:
        print("[COMPLIANCE] Screen lock policy enforced")
        _run_command(
            [
                "reg",
                "add",
                r"HKCU\Control Panel\Desktop",
                "/v",
                "ScreenSaveTimeOut",
                "/t",
                "REG_SZ",
                "/d",
                "600",
                "/f",
            ]
        )
    except Exception:
        print("[COMPLIANCE] enforcement failed")


def _enforce_usb_restriction() -> None:
    """Disable USB storage by setting USBSTOR Start to 4."""
    if os.name != "nt":
        return
    try:
        print("[COMPLIANCE] USB storage disabled")
        _run_command(
            [
                "reg",
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                "/v",
                "Start",
                "/t",
                "REG_DWORD",
                "/d",
                "4",
                "/f",
            ]
        )
    except Exception:
        print("[COMPLIANCE] enforcement failed")


class ComplianceCollector:
    """
    Windows compliance collector for basic endpoint security controls.

    Periodically emits a single COMPLIANCE_STATUS event with aggregated
    boolean controls and a simple compliance_score.
    """

    def __init__(self, config: Dict[str, Any]):
        cfg = config.get("compliance", {}) or {}
        self.interval = float(cfg.get("interval_sec", DEFAULT_INTERVAL_SEC))
        # Default to enforcement ON unless explicitly disabled in config.
        if "compliance_enforce" in config:
            enforce_flag = config.get("compliance_enforce")
        elif "enforce" in cfg:
            enforce_flag = cfg.get("enforce")
        else:
            enforce_flag = True
        self.enforce = bool(enforce_flag)
        self.last_run = 0.0

    def start(self) -> None:
        """
        No background thread needed; compliance checks are lightweight and
        performed lazily from flush_if_needed().
        """
        self.last_run = 0.0

    def _run_checks(self) -> Dict[str, bool]:
        """
        Run all compliance checks, defaulting to False on any failure.
        Never raises.
        """
        controls = {
            "firewall_enabled": False,
            "disk_encryption": False,
            "screen_lock_policy": False,
            "antivirus_running": False,
            "usb_restricted": False,
        }
        if os.name != "nt":
            return controls

        try:
            controls["firewall_enabled"] = _check_firewall_enabled()
        except Exception:
            controls["firewall_enabled"] = False

        try:
            controls["disk_encryption"] = _check_disk_encryption()
        except Exception:
            controls["disk_encryption"] = False

        try:
            controls["screen_lock_policy"] = _check_screen_lock_policy()
        except Exception:
            controls["screen_lock_policy"] = False

        try:
            controls["antivirus_running"] = _check_antivirus_running()
        except Exception:
            controls["antivirus_running"] = False

        try:
            controls["usb_restricted"] = _check_usb_restricted()
        except Exception:
            controls["usb_restricted"] = False

        return controls

    def flush_if_needed(self) -> Optional[Dict[str, Any]]:
        """
        Run compliance checks at most once per interval and emit a
        COMPLIANCE_STATUS event. Returns None if not time yet or on
        any unexpected failure.
        """
        try:
            now = time.time()
            if now - self.last_run < self.interval:
                return None

            self.last_run = now

            # First snapshot of current state.
            controls_before = self._run_checks()
            controls_after = controls_before.copy()

            # Track which controls we attempted to enforce AND which actually flipped to compliant.
            enforced: List[str] = []

            if self.enforce:
                try:
                    # Decide which controls need enforcement based on initial snapshot.
                    need_firewall = not controls_before.get("firewall_enabled", False)
                    need_screen = not controls_before.get("screen_lock_policy", False)
                    need_usb = not controls_before.get("usb_restricted", False)

                    if need_firewall:
                        _enforce_firewall()
                    if need_screen:
                        _enforce_screen_lock()
                    if need_usb:
                        _enforce_usb_restriction()

                    # Re-check after attempted enforcement to report latest state.
                    controls_after = self._run_checks()

                    # Only mark as enforced if the control is now actually compliant.
                    if need_firewall and controls_after.get("firewall_enabled"):
                        enforced.append("firewall")
                    if need_screen and controls_after.get("screen_lock_policy"):
                        enforced.append("screen_lock")
                    if need_usb and controls_after.get("usb_restricted"):
                        enforced.append("usb_restricted")
                except Exception:
                    # Never allow enforcement to crash the agent; individual helpers already log failures.
                    print("[COMPLIANCE] enforcement failed")

            controls = controls_after
            passed = sum(1 for v in controls.values() if v)
            total = 5
            compliance_score = int((passed / float(total)) * 100) if total else 0

            event: Dict[str, Any] = {
                "event_type": "COMPLIANCE_STATUS",
                "controls": controls,
                "compliance_score": compliance_score,
                "timestamp": now,
            }
            if enforced:
                event["enforced"] = enforced
            return event
        except Exception:
            return None


"""
User Session / Auth Presence Collector (Windows only).

Provides session-level CONTEXT for behavior correlation only.
NOT a full auth log collector; NOT Event Log analysis; NOT login/failure detection.

Privacy: NO usernames, NO login IDs/SIDs, NO credentials, NO login timestamps.
Only: session active (bool), duration bucket, is_admin (bool).
"""
import os
import time
from typing import Any, Dict, Optional

# Aggregation window (seconds); align with other collectors
DEFAULT_AGGREGATION_SEC = 30.0


def _session_active_windows() -> bool:
    """True if current process is in an interactive user session (session ID > 0). No user identity collected."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        pid = kernel32.GetCurrentProcessId()
        session_id = ctypes.c_uint()
        if kernel32.ProcessIdToSessionId(pid, ctypes.byref(session_id)):
            return session_id.value > 0
    except Exception:
        pass
    return False


def _is_admin_windows() -> bool:
    """True if current process has admin privileges. No user identity collected."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _duration_bucket(minutes: float) -> str:
    """Bucket session duration for privacy (no exact timestamps)."""
    if minutes < 30:
        return "<30"
    if minutes <= 120:
        return "30-120"
    return ">120"


def _severity(active: bool, duration_bucket: str, is_admin: bool) -> str:
    """LOW = normal; MEDIUM = very long session (>120 min) for potential correlation with high activity elsewhere."""
    if not active:
        return "LOW"
    if duration_bucket == ">120":
        return "MEDIUM"
    return "LOW"


class UserSessionCollector:
    """
    Lightweight session presence collector for Windows.
    Emits USER_SESSION_SUMMARY with active, duration_bucket, is_admin only.
    """

    def __init__(self, config: Dict[str, Any]):
        cfg = config.get("user_session", config.get("file_monitor", {}))
        self.interval = float(cfg.get("aggregation_sec", DEFAULT_AGGREGATION_SEC))
        self.last_flush = 0.0
        self.last_summary: Optional[Dict[str, Any]] = None
        self.session_start_time: Optional[float] = None

    def start(self) -> None:
        """No background thread; we poll in flush_if_needed()."""
        pass

    def _sample(self) -> Optional[Dict[str, Any]]:
        """Sample current session state. Returns None on any error (fail silently)."""
        try:
            active = _session_active_windows()
            is_admin = _is_admin_windows()

            now = time.time()
            if active:
                if self.session_start_time is None:
                    self.session_start_time = now
                duration_min = (now - self.session_start_time) / 60.0
                duration_bucket = _duration_bucket(duration_min)
            else:
                self.session_start_time = None
                duration_bucket = "<30"

            return {
                "active": active,
                "duration_bucket": duration_bucket,
                "is_admin": is_admin,
            }
        except Exception:
            return None

    def flush_if_needed(self) -> Optional[Dict[str, Any]]:
        """
        Emit USER_SESSION_SUMMARY at most every interval seconds, or when summary changes.
        Returns event dict or None. Never raises.
        """
        try:
            now = time.time()
            if now - self.last_flush < self.interval:
                sample = self._sample()
                if sample is None:
                    return None
                if self.last_summary is not None and sample == self.last_summary:
                    return None
                # State changed; emit even if window not elapsed
            else:
                sample = self._sample()
                if sample is None:
                    return None

            self.last_flush = now
            self.last_summary = sample.copy()

            severity = _severity(
                sample["active"],
                sample["duration_bucket"],
                sample["is_admin"],
            )
            event = {
                "event_type": "USER_SESSION_SUMMARY",
                "summary": sample,
                "severity": severity,
                "timestamp": now,
            }
            return event
        except Exception:
            return None

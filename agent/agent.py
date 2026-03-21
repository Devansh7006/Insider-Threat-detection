"""
Final agent with change-detection for USB and VPN (clean, runnable).
"""
from __future__ import annotations
print("AGENT FILE LOADED")

import os
import sys
import time
import json
import hashlib
import traceback
import subprocess
import socket
import threading
from typing import Dict, Any, Optional, Tuple, List
from agent.usb_monitor import start_usb_monitor

# ---------------- helper: robust import ----------------
def _import_with_fallback(package_name: str, attr: str, file_fallback: str = None):
    try:
        mod = __import__(package_name, fromlist=[attr])
        return getattr(mod, attr)
    except Exception:
        pass
    try:
        if file_fallback:
            rel = f".{os.path.basename(file_fallback).rsplit('.',1)[0]}"
            mod = __import__(rel, globals(), locals(), [attr], 0)
            return getattr(mod, attr)
    except Exception:
        pass
    if file_fallback:
        try:
            import importlib.util
            path = os.path.join(os.path.dirname(__file__), file_fallback)
            spec = importlib.util.spec_from_file_location(attr + "_fallback", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, attr)
        except Exception:
            pass
    raise ImportError(f"could not import {attr} from {package_name} (fallback tried: {file_fallback})")


# ---------------- core helpers with safe fallbacks ----------------
try:
    detect_os = _import_with_fallback("agent.os_detect", "detect_os", "os_detect.py")
except Exception:
    def detect_os():
        import platform
        return {
            "os_family": "Windows" if os.name == "nt" else "Linux",
            "os_name": platform.platform(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "is_admin": os.name == "nt" and bool(os.environ.get("USERNAME") == "Administrator")
        }

try:
    load_config = _import_with_fallback("agent.config_loader", "load_config", "config_loader.py")
except Exception:
    def load_config():
        cfg = {}
        cfg["backend_url"] = os.environ.get("ITD_BACKEND", "http://127.0.0.1:8000")
        cfg["agent_id"] = os.environ.get("ITD_AGENT_ID", "agent-unknown")
        return cfg

try:
    start_heartbeat = _import_with_fallback("agent.heartbeat", "start_heartbeat", "heartbeat.py")
except Exception:
    def start_heartbeat(config: Dict[str, Any]):
        backend = config.get("backend_url", "http://127.0.0.1:8000")
        agent_id = config.get("agent_id", "agent-unknown")
        interval = int(os.environ.get("ITD_HEARTBEAT_INTERVAL", "10"))
        def _hb_loop():
            try:
                import requests
            except Exception:
                print("[!] heartbeat fallback: 'requests' not installed; heartbeat disabled")
                return
            url = backend.rstrip("/") + "/api/v1/ingest/heartbeat"
            while True:
                payload = {"agent_id": agent_id, "os": detect_os(), "timestamp": time.time()}
                try:
                    r = requests.post(url, json=payload, timeout=4)
                    print(f"[HEARTBEAT] sent: {r.status_code}")
                except Exception as e:
                    print("[!] Heartbeat failed:", e)
                time.sleep(interval)
        t = threading.Thread(target=_hb_loop, daemon=True)
        t.start()
        return t

try:
    send_batch = _import_with_fallback("agent.sender", "send_batch", "sender.py")
except Exception:
    def send_batch(events: List[Dict[str, Any]], config: Dict[str, Any]):
        backend = config.get("backend_url", "http://127.0.0.1:8000")
        url = backend.rstrip("/") + "/api/v1/ingest"
        agent_id = config.get("agent_id", "agent-unknown")
        try:
            import requests
        except Exception:
            print("[!] send_batch fallback: 'requests' not installed. events not sent.")
            return {"status": "requests-not-installed"}
        payload = {"agent_id": agent_id, "events": events}
        try:
            r = requests.post(url, json=payload, timeout=6)
            print(f"[SEND_BATCH] sent: {r.status_code}")
            if r.headers.get("content-type","").startswith("application/json"):
                return r.json()
            return {"status": r.status_code}
        except Exception as e:
            print("[!] send_batch HTTP error:", e)
            return {"status": "error", "note": str(e)}

try:
    check_usb = _import_with_fallback("agent.usb_monitor", "check_usb", "usb_monitor.py")
except Exception:
    def check_usb():
        res = []
        if os.name == "nt":
            try:
                import string, ctypes
                bitmask = ctypes.cdll.kernel32.GetLogicalDrives()
                for i, d in enumerate(string.ascii_uppercase):
                    if bitmask & (1 << i):
                        drv = f"{d}:\\"
                        try:
                            if ctypes.cdll.kernel32.GetDriveTypeW(drv) == 2:
                                res.append({"mount": drv})
                        except Exception:
                            continue
            except Exception:
                pass
        else:
            for root in ("/media", "/run/media"):
                if os.path.isdir(root):
                    for user in os.listdir(root):
                        p = os.path.join(root, user)
                        if os.path.isdir(p):
                            for d in os.listdir(p):
                                res.append({"mount": os.path.join(p, d)})
        return res


# ----------------------- Configurable constants -----------------------
USB_SCAN_INTERVAL = int(os.environ.get("USB_SCAN_INTERVAL", "60"))
MAIN_LOOP_SLEEP = int(os.environ.get("MAIN_LOOP_SLEEP", "5"))
VPN_API_PORT = int(os.environ.get("VPN_API_PORT", "8001"))
VPN_API_MODULE = os.environ.get("VPN_API_MODULE", "agent.vpn_api")
STATE_FILE = os.path.join(os.path.dirname(__file__), "state.json")
VPN_CACHE_TTL = int(os.environ.get("VPN_CACHE_TTL", "30"))
USB_MAX_DEPTH = int(os.environ.get("USB_MAX_DEPTH", "2"))
USB_MAX_FILES = int(os.environ.get("USB_MAX_FILES", "10000"))

# FIX: single canonical compliance event_type — matches what main.py stores on
COMPLIANCE_EVENT_TYPE = "COMPLIANCE_STATUS"


# ----------------------- State persistence -----------------------
def _atomic_write(path: str, data: Dict[str, Any]):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state: Dict[str, Any]):
    try:
        _atomic_write(STATE_FILE, state)
    except Exception:
        print("[!] Failed to persist state:", traceback.format_exc())


# ----------------------- VPN helpers -----------------------
def _wait_for_port(host: str, port: int, timeout: float = 3.0, interval: float = 0.2) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=interval):
                return True
        except Exception:
            time.sleep(interval)
    return False

def start_vpn_api_subprocess(python_exe=None, port=VPN_API_PORT):
    python_exe = python_exe or sys.executable
    cmd = [python_exe, "-m", "uvicorn", f"{VPN_API_MODULE}:app",
           "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"]
    env = os.environ.copy()
    env["VPN_ANALYZER_PORT"] = str(port)
    try:
        stdout = open(os.path.join(os.getcwd(), "vpn_api.stdout.log"), "a")
        stderr = open(os.path.join(os.getcwd(), "vpn_api.stderr.log"), "a")
        proc = subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stderr)
        _wait_for_port("127.0.0.1", port, timeout=4.0)
        return proc
    except Exception as e:
        print("[!] Failed to start vpn_api subprocess:", e)
        return None

def fetch_vpn_analysis(port=VPN_API_PORT, timeout=6.0):
    try:
        import requests
    except Exception:
        return {"vpn": False, "note": "requests-not-installed"}
    try:
        r = requests.get(f"http://127.0.0.1:{port}/analyze", timeout=timeout)
        if r.status_code == 200:
            return r.json()
        return {"vpn": False, "note": f"status:{r.status_code}"}
    except Exception as e:
        return {"vpn": False, "note": f"error:{e}"}

def vpn_fingerprint(data):
    keys = ["ipv4", "ipv6", "isp", "country", "city", "blacklisted"]
    s = "|".join(str(data.get(k) or "") for k in keys)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ----------------------- USB helpers -----------------------
def mount_file_metadata(mount, max_depth=USB_MAX_DEPTH, max_files=USB_MAX_FILES):
    meta = {}
    mount = os.path.abspath(mount)
    if not os.path.exists(mount):
        return meta
    files_seen = 0
    mount_len = len(mount.rstrip(os.sep)) + 1
    for root, dirs, files in os.walk(mount):
        rel = root[mount_len:] if len(root) >= mount_len else ""
        depth = 0 if rel == "" else rel.count(os.sep) + 1
        if depth > max_depth:
            dirs[:] = []
            continue
        for f in files:
            if files_seen >= max_files:
                break
            try:
                full = os.path.join(root, f)
                st = os.stat(full)
                meta[full[mount_len:]] = [int(st.st_size), int(st.st_mtime)]
                files_seen += 1
            except Exception:
                continue
        if files_seen >= max_files:
            break
    return meta

def usb_fingerprint_from_meta(meta):
    items = sorted(meta.items(), key=lambda x: x[0])
    s = "\n".join(f"{p}:{int(v[0])}:{int(v[1])}" for p, v in items)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def compute_usb_diff(old_meta, new_meta):
    old_keys = set(old_meta.keys())
    new_keys = set(new_meta.keys())
    modified = sum(1 for k in old_keys & new_keys if old_meta.get(k) != new_meta.get(k))
    return {"added": len(new_keys - old_keys), "removed": len(old_keys - new_keys), "modified": modified}


# ----------------------- Print helpers -----------------------
def print_vpn_summary(vpn_info):
    print("\n[VPN ANALYSIS]")
    for k in ("ipv4", "ipv6", "country", "city", "isp", "vpn", "blacklisted"):
        print(f"  {k}: {vpn_info.get(k)}")
    if vpn_info.get("note"):
        print("  Note:", vpn_info.get("note"))

def print_usb_summary(mount, meta, diff, last_send_time):
    print("\n[USB ANALYSIS]")
    print(f"  mount: {mount}")
    print(f"  total files: {len(meta)}")
    if diff:
        print(f"  added: {diff.get('added')} removed: {diff.get('removed')} modified: {diff.get('modified')}")
    if last_send_time:
        print(f"  last sent: {time.ctime(last_send_time)}")


# ----------------------- Compliance event builder -----------------------
def build_compliance_event(agent_id: str, os_info: Dict[str, Any], raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    FIX: Normalise whatever ComplianceCollector.flush_if_needed() returns into
    a flat event dict with event_type = COMPLIANCE_STATUS.

    The collector may return fields at the top level OR nested under a
    "compliance" key.  We handle both shapes here so main.py always gets
    compliance_score / controls / enforced at the top level.
    """
    inner = raw.get("compliance") or raw
    return {
        "event_type": COMPLIANCE_EVENT_TYPE,          # always "COMPLIANCE_STATUS"
        "agent_id": agent_id,
        "os": os_info,
        "compliance_score": inner.get("compliance_score") or raw.get("compliance_score"),
        "controls": inner.get("controls") or raw.get("controls", {}),
        "enforced": inner.get("enforced") or raw.get("enforced", []),
        "timestamp": raw.get("timestamp") or time.time(),
    }


# ----------------------- Main agent -----------------------
def main():
    print("[*] Agent starting...")
    print("INSIDE MAIN FUNCTION")

    state = load_state()
    usb_state = state.get("usb", {})
    vpn_state = state.get("vpn", {})

    vpn_proc = None
    collectors: List = []

    try:
        os_info = detect_os()
        os_type = os_info.get("os_family", "Unknown")
        print(f"[*] Detected OS: {os_type}")

        config = load_config() or {}
        agent_id = config.get("agent_id", "agent-unknown")
        print("AGENT ID BEING USED:", agent_id)
        print("BACKEND URL:", config.get("backend_url"))

        def usb_send_wrapper(event):
            event["agent_id"] = agent_id
            event["os"] = os_info
            send_batch([event], config)

        usb_thread = threading.Thread(target=start_usb_monitor, args=(usb_send_wrapper,), daemon=True)
        usb_thread.start()

        try:
            vpn_proc = start_vpn_api_subprocess()
            if vpn_proc:
                print(f"[*] VPN Analyzer subprocess started (PID {getattr(vpn_proc, 'pid', '?')})")
            else:
                print("[*] VPN Analyzer subprocess not started (ok if not needed)")
        except Exception:
            print("[!] Failed to start VPN subprocess:", traceback.format_exc())
            vpn_proc = None

        try:
            start_heartbeat(config)
        except Exception:
            print("[!] Heartbeat start failed:", traceback.format_exc())

        # --- initial vpn check ---
        try:
            vpn_info = fetch_vpn_analysis()
            if "note" in vpn_info and str(vpn_info.get("note")).startswith("error"):
                print("[!] Initial VPN check error (will retry):", vpn_info.get("note"))
            else:
                vpn_fp = vpn_fingerprint(vpn_info)
                if vpn_state.get("fp") != vpn_fp:
                    print_vpn_summary(vpn_info)
                    try:
                        send_batch([{"event_type": "VPN_EVENT", "agent_id": agent_id,
                                     "os": os_info, "vpn_info": vpn_info, "timestamp": time.time()}], config)
                    except Exception as e:
                        print("[!] Failed to send VPN event:", e)
                    vpn_state["fp"] = vpn_fp
                    vpn_state["last_sent"] = time.time()
                    state["vpn"] = vpn_state
                    save_state(state)
                else:
                    print("[*] VPN unchanged since last send")
        except Exception:
            print("[!] Initial VPN check failed:", traceback.format_exc())

        # --- initial usb scan ---
        print("RAW USB DATA:", check_usb())
        try:
            raw = check_usb() or []
            print("DEBUG USB RAW:", raw)
            for e in raw:
                mount = e.get("mount")
                if not mount:
                    continue
                try:
                    meta = mount_file_metadata(mount)
                    fp = usb_fingerprint_from_meta(meta)
                    prev = usb_state.get(mount, {})
                    if prev.get("fp") != fp:
                        diff = compute_usb_diff(prev.get("meta", {}), meta) if prev.get("meta") else None
                        print_usb_summary(mount, meta, diff, prev.get("last_sent"))
                        event = {
                            "event_type": "USB_EVENT", "agent_id": agent_id, "os": os_info,
                            "mount": mount, "fingerprint": fp,
                            "summary": {"total_files": len(meta),
                                        "added": diff.get("added") if diff else None,
                                        "removed": diff.get("removed") if diff else None,
                                        "modified": diff.get("modified") if diff else None},
                            "timestamp": time.time()
                        }
                        try:
                            send_batch([event], config)
                        except Exception as e:
                            print("[!] Failed to send USB event:", e)
                        usb_state[mount] = {"fp": fp, "meta": meta, "last_sent": time.time()}
                        state["usb"] = usb_state
                        save_state(state)
                    else:
                        print(f"[*] USB mount {mount} unchanged since last send")
                except Exception:
                    print("[!] USB initial check failed for mount", mount, traceback.format_exc())
        except Exception:
            print("[!] Initial USB scan failed:", traceback.format_exc())

        # --- Collectors init (Windows only) ---
        def _win_collector(module, cls, fallback):
            if not (os_type and os_type.lower().startswith("windows")):
                return None
            try:
                Cls = _import_with_fallback(module, cls, fallback)
                obj = Cls(config)
                obj.start()
                return obj
            except Exception:
                print(f"[!] {cls} not started (optional):", traceback.format_exc())
                return None

        file_activity_collector = _win_collector(
            "agent.collectors.windows.file_activity", "FileActivityCollector",
            os.path.join("collectors", "windows", "file_activity.py"))

        process_activity_collector = _win_collector(
            "agent.collectors.windows.process_activity", "ProcessActivityCollector",
            os.path.join("collectors", "windows", "process_activity.py"))

        clipboard_activity_collector = _win_collector(
            "agent.collectors.windows.clipboard_activity", "ClipboardActivityCollector",
            os.path.join("collectors", "windows", "clipboard_activity.py"))

        network_activity_collector = _win_collector(
            "agent.collectors.windows.network_activity", "NetworkActivityCollector",
            os.path.join("collectors", "windows", "network_activity.py"))

        user_session_collector = _win_collector(
            "agent.collectors.windows.user_session", "UserSessionCollector",
            os.path.join("collectors", "windows", "user_session.py"))

        # Compliance collector — loaded directly from file path
        compliance_collector = None
        try:
            if os_type and os_type.lower().startswith("windows"):
                import importlib.util
                comp_path = os.path.join(os.path.dirname(__file__), "collectors", "windows", "compliance.py")
                if os.path.exists(comp_path):
                    spec = importlib.util.spec_from_file_location("compliance_collector_module", comp_path)
                    if spec and spec.loader:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        ComplianceCollector = getattr(mod, "ComplianceCollector", None)
                        if ComplianceCollector:
                            compliance_collector = ComplianceCollector(config)
                            compliance_collector.start()
                            interval = getattr(compliance_collector, "interval", 300)
                            print(f"[*] Compliance collector started (every {int(interval)}s)")
                        else:
                            print("[!] ComplianceCollector class not found in compliance.py")
                else:
                    print(f"[!] compliance.py not found at {comp_path}")
        except Exception:
            print("[!] Compliance collector not started (optional):", traceback.format_exc())

        # Auth collectors
        try:
            if os_type and os_type.lower().startswith("windows"):
                try:
                    collectors = [_import_with_fallback("agent.collectors.windows.auth", "collect_auth_events",
                                                         os.path.join("collectors", "windows", "auth.py"))]
                except Exception:
                    collectors = []
            elif os_type and os_type.lower().startswith("linux"):
                try:
                    collectors = [_import_with_fallback("agent.collectors.linux.auth", "collect_auth_events",
                                                         os.path.join("collectors", "linux", "auth.py"))]
                except Exception:
                    collectors = []
            else:
                collectors = []
        except Exception:
            print("[!] Failed to load collectors:", traceback.format_exc())
            collectors = []

        # main loop
        last_usb_scan = time.time()
        last_vpn_query = time.time()

        while True:
            batch: List[Dict[str, Any]] = []

            if file_activity_collector is not None:
                try:
                    ev = file_activity_collector.flush_if_needed()
                    if ev:
                        ev.setdefault("agent_id", agent_id)
                        ev.setdefault("os", os_info)
                        batch.append(ev)
                        s = ev.get("summary", {})
                        print(f"\n[FILE] writes:{s.get('write',0)} deletes:{s.get('delete',0)} severity:{ev.get('severity','N/A')}")
                except Exception:
                    print("[!] File activity flush error:", traceback.format_exc())

            if process_activity_collector is not None:
                try:
                    ev = process_activity_collector.flush_if_needed()
                    if ev:
                        ev.setdefault("agent_id", agent_id)
                        ev.setdefault("os", os_info)
                        batch.append(ev)
                        s = ev.get("summary", {})
                        print(f"\n[PROCESS] {len(s)} distinct, total:{sum(s.values())} severity:{ev.get('severity','N/A')}")
                except Exception:
                    print("[!] Process activity flush error:", traceback.format_exc())

            if clipboard_activity_collector is not None:
                try:
                    ev = clipboard_activity_collector.flush_if_needed()
                    if ev:
                        ev.setdefault("agent_id", agent_id)
                        ev.setdefault("os", os_info)
                        batch.append(ev)
                        s = ev.get("summary", {})
                        print(f"\n[CLIPBOARD] copy_events:{s.get('copy_events',0)} severity:{ev.get('severity','N/A')}")
                except Exception:
                    print("[!] Clipboard activity flush error:", traceback.format_exc())

            if network_activity_collector is not None:
                try:
                    ev = network_activity_collector.flush_if_needed()
                    if ev:
                        ev.setdefault("agent_id", agent_id)
                        ev.setdefault("os", os_info)
                        batch.append(ev)
                        s = ev.get("summary", {})
                        print(f"\n[NETWORK] sent:{s.get('bytes_sent',0)} recv:{s.get('bytes_received',0)} severity:{ev.get('severity','N/A')}")
                except Exception:
                    print("[!] Network activity flush error:", traceback.format_exc())

            if user_session_collector is not None:
                try:
                    ev = user_session_collector.flush_if_needed()
                    if ev:
                        ev.setdefault("agent_id", agent_id)
                        ev.setdefault("os", os_info)
                        batch.append(ev)
                        s = ev.get("summary", {})
                        print(f"\n[SESSION] active:{s.get('active')} bucket:{s.get('duration_bucket')} admin:{s.get('is_admin')}")
                except Exception:
                    print("[!] User session flush error:", traceback.format_exc())

            # FIX: Compliance flush — normalise via build_compliance_event()
            # so event_type is always "COMPLIANCE_STATUS" and all fields are
            # at the top level where main.py's ingest handler reads them.
            if compliance_collector is not None:
                try:
                    raw_compliance = compliance_collector.flush_if_needed()
                    if raw_compliance:
                        compliance_event = build_compliance_event(agent_id, os_info, raw_compliance)
                        batch.append(compliance_event)
                        print(f"\n[COMPLIANCE] event_type={compliance_event['event_type']} "
                              f"score={compliance_event.get('compliance_score')} "
                              f"controls={list((compliance_event.get('controls') or {}).keys())}")
                except Exception:
                    print("[!] Compliance flush error:", traceback.format_exc())

            for collector in collectors:
                try:
                    evs = collector(config) or []
                    for ev in evs:
                        ev.setdefault("agent_id", agent_id)
                        ev.setdefault("os", os_info)
                        if ev.get("event_type") == "USER_LOGIN":
                            print(f"\n[AUTH] User:{ev.get('username')} logon:{ev.get('logon_type')} "
                                  f"time:{time.ctime(ev.get('timestamp', time.time()))}")
                    batch.extend(evs)
                except Exception:
                    print("[!] Collector error:", traceback.format_exc())

            now = time.time()

            if now - last_usb_scan >= USB_SCAN_INTERVAL:
                last_usb_scan = now
                try:
                    for e in (check_usb() or []):
                        mount = e.get("mount")
                        if not mount:
                            continue
                        try:
                            meta = mount_file_metadata(mount)
                            fp = usb_fingerprint_from_meta(meta)
                            prev = usb_state.get(mount, {})
                            if prev.get("fp") != fp:
                                diff = compute_usb_diff(prev.get("meta", {}), meta) if prev.get("meta") else None
                                print_usb_summary(mount, meta, diff, prev.get("last_sent"))
                                batch.append({
                                    "event_type": "USB_EVENT", "agent_id": agent_id, "os": os_info,
                                    "mount": mount, "fingerprint": fp,
                                    "summary": {"total_files": len(meta),
                                                "added": diff.get("added") if diff else None,
                                                "removed": diff.get("removed") if diff else None,
                                                "modified": diff.get("modified") if diff else None},
                                    "timestamp": time.time()
                                })
                                usb_state[mount] = {"fp": fp, "meta": meta, "last_sent": time.time()}
                                state["usb"] = usb_state
                                save_state(state)
                            else:
                                print(f"[*] USB mount {mount} unchanged")
                        except Exception:
                            print("[!] USB periodic check failed for mount", mount, traceback.format_exc())
                except Exception:
                    print("[!] USB periodic scan failed:", traceback.format_exc())

            if now - last_vpn_query >= VPN_CACHE_TTL:
                last_vpn_query = now
                try:
                    vpn_info = fetch_vpn_analysis()
                    if "note" in vpn_info and str(vpn_info.get("note")).startswith("error"):
                        print("[!] VPN periodic error — keeping last state:", vpn_info.get("note"))
                    else:
                        vpn_fp = vpn_fingerprint(vpn_info)
                        if vpn_fp != vpn_state.get("fp"):
                            print_vpn_summary(vpn_info)
                            batch.append({"event_type": "VPN_EVENT", "agent_id": agent_id,
                                          "os": os_info, "vpn_info": vpn_info, "timestamp": time.time()})
                            vpn_state["fp"] = vpn_fp
                            vpn_state["last_sent"] = time.time()
                            state["vpn"] = vpn_state
                            save_state(state)
                except Exception:
                    print("[!] VPN periodic fetch failed:", traceback.format_exc())

            if batch:
                try:
                    send_batch(batch, config)
                except Exception as e:
                    print("[!] send_batch failed:", e)

            time.sleep(MAIN_LOOP_SLEEP)

    except KeyboardInterrupt:
        print("\n[!] Agent interrupted by user - shutting down")
    except Exception:
        print("[!] Agent crashed:", traceback.format_exc())
    finally:
        if vpn_proc:
            try:
                vpn_proc.terminate()
                time.sleep(1.0)
                if vpn_proc.poll() is None:
                    vpn_proc.kill()
            except Exception:
                pass
        try:
            state["usb"] = usb_state
            state["vpn"] = vpn_state
            save_state(state)
        except Exception:
            pass


if __name__ == "__main__":
    main()

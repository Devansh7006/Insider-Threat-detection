import os
import time
import platform
import hashlib
import psutil
import requests

# ================= CONFIG =================
BACKEND_URL = "http://127.0.0.1:8000/api/v1/ingest"
AGENT_ID = "agent-001"
SCAN_INTERVAL = 5
MAX_FILES_SCAN = 10000

SUSPICIOUS_EXT = {".exe", ".bat", ".ps1", ".dll", ".zip", ".rar", ".7z", ".docm", ".xlsm"}

# ================= USB DETECTION =================
def get_removable_drives():
    drives = []
    if platform.system() == "Windows":
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drive = f"{chr(65+i)}:\\"
                dtype = ctypes.windll.kernel32.GetDriveTypeW(drive)
                if dtype == 2:  # removable
                    drives.append(drive)
    return drives


# ================= FILE SCAN =================
def scan_usb(mount):
    file_count = 0
    total_size = 0
    executable_count = 0
    suspicious_count = 0

    fingerprint_builder = []

    for root, _, files in os.walk(mount):
        for f in files:
            if file_count >= MAX_FILES_SCAN:
                break

            try:
                full = os.path.join(root, f)
                stat = os.stat(full)

                size = stat.st_size
                ext = os.path.splitext(f)[1].lower()

                file_count += 1
                total_size += size

                if ext == ".exe":
                    executable_count += 1

                if ext in SUSPICIOUS_EXT:
                    suspicious_count += 1

                fingerprint_builder.append(f"{f}:{size}:{int(stat.st_mtime)}")

            except:
                continue

    fingerprint_string = "\n".join(sorted(fingerprint_builder))
    fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()

    return {
        "file_count": file_count,
        "total_size_mb": round(total_size / (1024*1024), 2),
        "executables": executable_count,
        "suspicious_files": suspicious_count,
        "fingerprint": fingerprint
    }


# ================= RISK ENGINE =================
def calculate_risk(data):
    score = 0
    reasons = []

    if data["file_count"] > 3000:
        score += 2
        reasons.append("High file count")

    if data["total_size_mb"] > 1000:
        score += 2
        reasons.append("Large data volume")

    if data["executables"] > 0:
        score += 2
        reasons.append("Executable files present")

    if data["suspicious_files"] > 0:
        score += 3
        reasons.append("Suspicious file types detected")

    if score >= 6:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "reasons": reasons}


# ================= SEND TO BACKEND =================
def send_usb_event(event):
    payload = {
        "agent_id": AGENT_ID,
        "events": [event]
    }

    try:
        r = requests.post(BACKEND_URL, json=payload)
        print("[USB SENT]", r.status_code)
    except Exception as e:
        print("[USB SEND ERROR]", e)


# ================= MAIN ENGINE =================
def start_usb_monitor():
    print("USB FULL ENGINE STARTED")

    known = {}
    current_mounts = get_removable_drives()

    # INITIAL SCAN (important: no need to reinsert USB)
    for mount in current_mounts:
        data = scan_usb(mount)
        risk = calculate_risk(data)

        known[mount] = data["fingerprint"]

        event = {
            "event_type": "USB_INITIAL",
            "mount": mount,
            "intel": data,
            "risk": risk,
            "timestamp": time.time()
        }

        send_usb_event(event)

    while True:
        try:
            mounts = get_removable_drives()

            # INSERTED
            for mount in mounts:
                if mount not in known:
                    print("[USB INSERTED]", mount)

                    data = scan_usb(mount)
                    risk = calculate_risk(data)

                    known[mount] = data["fingerprint"]

                    event = {
                        "event_type": "USB_INSERT",
                        "mount": mount,
                        "intel": data,
                        "risk": risk,
                        "timestamp": time.time()
                    }

                    send_usb_event(event)

            # REMOVED
            for mount in list(known.keys()):
                if mount not in mounts:
                    print("[USB REMOVED]", mount)

                    event = {
                        "event_type": "USB_REMOVE",
                        "mount": mount,
                        "timestamp": time.time()
                    }

                    send_usb_event(event)

                    del known[mount]

            # MODIFICATION CHECK
            for mount in mounts:
                data = scan_usb(mount)
                new_fp = data["fingerprint"]

                if known.get(mount) != new_fp:
                    print("[USB MODIFIED]", mount)

                    risk = calculate_risk(data)

                    event = {
                        "event_type": "USB_MODIFIED",
                        "mount": mount,
                        "intel": data,
                        "risk": risk,
                        "timestamp": time.time()
                    }

                    send_usb_event(event)

                    known[mount] = new_fp

            time.sleep(SCAN_INTERVAL)

        except Exception as e:
            print("[USB ENGINE ERROR]", e)
            time.sleep(5)


if __name__ == "__main__":
    start_usb_monitor()
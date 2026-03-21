import time
import psutil
import requests
from .device_intel import analyze_usb

BACKEND_URL = "http://127.0.0.1:8000/api/v1/ingest"
SCAN_DELAY = 2


def get_removable_drives():
    """
    TEMP DEVELOPMENT MODE:
    Treat all drives except C: as removable
    so we can test insert/remove detection.
    """
    drives = set()

    for p in psutil.disk_partitions(all=False):
        if not p.device.startswith("C"):
            drives.add(p.device)

    return drives


def send_event(payload):
    try:
        r = requests.post(BACKEND_URL, json=payload, timeout=5)
        print(f"[USB SEND] {r.status_code}")
    except Exception as e:
        print("[USB SEND ERROR]", e)


def start_usb_monitor(agent_id):
    print("[USB] Monitor started")

    known_drives = get_removable_drives()

    while True:
        try:
            current_drives = get_removable_drives()

            inserted = current_drives - known_drives
            removed = known_drives - current_drives

            # ---------------- INSERTED ----------------
            for drive in inserted:
                print(f"[USB INSERTED] {drive}")

                intel = analyze_usb(drive)

                payload = {
                    "agent_id": agent_id,
                    "events": [
                        {
                            "event_type": "USB_REALTIME",
                            "drive": drive,
                            "action": "inserted",
                            "intel": intel,
                            "timestamp": time.time()
                        }
                    ]
                }

                send_event(payload)

            # ---------------- REMOVED ----------------
            for drive in removed:
                print(f"[USB REMOVED] {drive}")

                payload = {
                    "agent_id": agent_id,
                    "events": [
                        {
                            "event_type": "USB_REALTIME",
                            "drive": drive,
                            "action": "removed",
                            "timestamp": time.time()
                        }
                    ]
                }

                send_event(payload)

            known_drives = current_drives
            time.sleep(SCAN_DELAY)

        except Exception as e:
            print("[USB MONITOR ERROR]", e)
            time.sleep(5)
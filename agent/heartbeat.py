"""
Robust Heartbeat Module
- Sends periodic heartbeat to backend
- Includes timestamp + optional system info
- Handles failures gracefully
"""

import threading
import time
import requests
import socket
from typing import Dict, Any


def start_heartbeat(config: Dict[str, Any]):
    backend = config.get("backend_url")

    if not backend:
        print("[HEARTBEAT] ❌ No backend_url configured. Disabled.")
        return None

    backend = backend.rstrip("/")
    agent_id = config.get("agent_id") or socket.gethostname()
    interval = int(config.get("heartbeat_interval", 10))

    print(f"[HEARTBEAT] Running → {backend} | Agent: {agent_id}")

    def loop():
        while True:
            try:
                payload = {
                    "agent_id": agent_id,
                    "timestamp": time.time(),
                    "hostname": socket.gethostname()
                }

                url = f"{backend}/api/v1/ingest/heartbeat"

                r = requests.post(url, json=payload, timeout=10)

                if r.status_code == 200:
                    print("[HEARTBEAT] ✅ sent")
                else:
                    print("[HEARTBEAT] ⚠️ status:", r.status_code)

            except requests.exceptions.Timeout:
                print("[HEARTBEAT] ⏱ timeout")

            except requests.exceptions.ConnectionError:
                print("[HEARTBEAT] 🔌 connection failed")

            except Exception as e:
                print("[HEARTBEAT] ❌ error:", e)

            time.sleep(interval)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t

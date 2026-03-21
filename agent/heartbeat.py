"""
Stable Heartbeat Module
"""

import threading
import time
import requests
from typing import Dict, Any


def start_heartbeat(config: Dict[str, Any]):

    backend = config.get("backend_url")

    if not backend:
        print("[HEARTBEAT] No backend_url configured. Heartbeat disabled.")
        return None

    backend = backend.rstrip("/")
    agent_id = config.get("agent_id", "agent-unknown")
    interval = int(config.get("heartbeat_interval", 10))

    print(f"[HEARTBEAT] Running → {backend}")

    def loop():
        while True:
            try:
                payload = {
                    "agent_id": agent_id,
                    "timestamp": time.time()
                }

                url = f"{backend}/api/v1/ingest/heartbeat"

                r = requests.post(url, json=payload, timeout=20)

                print("[HEARTBEAT] sent:", r.status_code)

            except Exception as e:
                print("[HEARTBEAT] failed:", e)

            time.sleep(interval)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t
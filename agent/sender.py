import requests
import traceback
from typing import List, Dict, Any

def send_batch(events: List[Dict[str, Any]], config: Dict[str, Any]) -> dict:
    backend = config.get("backend_url", "").rstrip("/")
    agent_id = config.get("agent_id", "agent-unknown")

    payload = {"agent_id": agent_id, "events": events}

    try:
        r = requests.post(f"{backend}/api/v1/ingest", json=payload, timeout=8)
        print("[SEND_BATCH] sent:", r.status_code)
        return {"status_code": r.status_code}
    except Exception as e:
        print("[SEND_BATCH] failed:", e)
        return {"error": str(e), "trace": traceback.format_exc()}


def send_heartbeat(agent_id: str, os_info: Dict[str, Any], config: Dict[str, Any]) -> dict:
    backend = config.get("backend_url", "").rstrip("/")

    payload = {"agent_id": agent_id, "os": os_info}

    try:
        r = requests.post(f"{backend}/api/v1/ingest/heartbeat", json=payload, timeout=5)
        return {"status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}
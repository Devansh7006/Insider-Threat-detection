from fastapi import APIRouter, Request
from typing import Dict, Any, List
import time

router = APIRouter()

# In-memory store (you are already using this pattern)
SYSTEM_STATE: Dict[str, Dict[str, Any]] = {}


@router.post("/api/v1/ingest")
async def ingest_events(payload: Dict[str, Any]):
    agent_id = payload.get("agent_id")
    events: List[Dict[str, Any]] = payload.get("events", [])

    if not agent_id:
        return {"status": "error", "reason": "agent_id missing"}

    system = SYSTEM_STATE.setdefault(agent_id, {
        "agent_id": agent_id,
        "last_seen": None,
        "usb": {},
        "vpn": {},
        "auth": {"logins": 0, "last_user": None},
        "events": []
    })

    system["last_seen"] = time.time()
    system["os"] = payload.get("os", {})
    save_event(agent_id, "HEARTBEAT", payload)

    for event in events:
        event_type = event.get("event_type")
        system["events"].append(event)

        # ---------- AUTH ----------
        if event_type == "USER_LOGIN":
            system["auth"]["logins"] += 1
            system["auth"]["last_user"] = event.get("username")

        # ---------- VPN (THIS WAS MISSING) ----------
        elif event_type == "VPN_EVENT":
            system["vpn"] = event.get("vpn_info", {})

        # ---------- USB ----------
        elif event_type == "USB_EVENT":
            system["usb"] = {
                "mount": event.get("mount"),
                "summary": event.get("summary"),
                "last_seen": event.get("timestamp")
            }

    return {"status": "ok"}


@router.get("/api/v1/system/{agent_id}")
async def get_system(agent_id: str):
    system = SYSTEM_STATE.get(agent_id)
    if not system:
        return {"error": "agent not found"}
    return system

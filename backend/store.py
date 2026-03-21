# backend/store.py
import time
from typing import Dict, Any, List

# in-memory store (simple)
systems: Dict[str, Dict[str, Any]] = {}
events: Dict[str, List[Dict[str, Any]]] = {}

def upsert_system(agent_id: str, os_info: Dict[str, Any]):
    now = time.time()
    s = systems.setdefault(agent_id, {})
    # keep existing fields, update what's provided
    s["agent_id"] = agent_id
    s["os"] = os_info or s.get("os", {})
    s["last_seen"] = now
    s.setdefault("auth", {"logins": 0, "last_user": None})
    s.setdefault("usb", {})
    s.setdefault("vpn", {})
    return s

def add_event(agent_id: str, ev: Dict[str, Any]):
    ev_copy = dict(ev)
    ev_copy["received_at"] = time.time()
    events.setdefault(agent_id, []).append(ev_copy)
    # ensure system exists and update last_seen
    s = systems.setdefault(agent_id, {})
    s["last_seen"] = time.time()
    return ev_copy

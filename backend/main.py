from fastapi import FastAPI
import time
from fastapi.middleware.cors import CORSMiddleware
from .risk_engine import compute_risk
from .database import init_db, save_event
import sys
sys.stdout.reconfigure(encoding='utf-8')

app = FastAPI(title="Insider Threat Detection Backend")

init_db()

# ------------------ No Cache Middleware ------------------

async def no_cache_middleware(request, call_next):
    response = await call_next(request)
    if request.method == "GET":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response

app.middleware("http")(no_cache_middleware)

# ------------------ CORS ------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ In-memory state ------------------

systems = {}
events = {}

# All event_type strings that carry compliance data.
# compliance.py emits exactly "COMPLIANCE_STATUS" — the set handles any
# future rename without breaking existing data.
_COMPLIANCE_TYPES = {"COMPLIANCE_STATUS", "COMPLIANCE_EVENT"}

# ------------------ INGEST ------------------

@app.post("/api/v1/ingest")
async def ingest(payload: dict):

    agent_id = payload["agent_id"]
    evs = payload.get("events", [])

    system = systems.setdefault(agent_id, {
        "agent_id": agent_id,
        "username": None,
        "last_seen": None,
        "os": {},
        "usb": {},
        "vpn": {},
        "compliance": None,
        "auth": {
            "logins": 0,
            "last_user": None
        }
    })

    system["last_seen"] = time.time()
    events.setdefault(agent_id, [])

    for ev in evs:

        ev["received_at"] = time.time()
        events[agent_id].append(ev)
        save_event(agent_id, ev.get("event_type"), ev)

        # Populate system["os"] and username from event (heartbeat may not have run yet)
        if ev.get("os"):
            system["os"] = ev.get("os")
            u = ev.get("os", {}).get("username")
            if u:
                system["username"] = u

        event_type = (ev.get("event_type") or "").upper()

        # USB EVENTS
        if event_type.startswith("USB") and event_type != "USB_REMOVE":
            system["usb"] = {
                "mount": ev.get("mount"),
                "intel": ev.get("intel"),
                "risk": ev.get("risk"),
                "last_event": ev.get("event_type"),
                "timestamp": ev.get("timestamp")
            }

        elif event_type == "USB_REMOVE":
            system["usb"] = {
                "mount": ev.get("mount"),
                "status": "removed",
                "timestamp": ev.get("timestamp")
            }

        # VPN EVENT
        elif event_type == "VPN_EVENT":
            system["vpn"] = ev.get("vpn_info", {})

        # LOGIN EVENT
        elif event_type == "USER_LOGIN":
            system["auth"]["logins"] += 1
            system["auth"]["last_user"] = ev.get("username")

        # COMPLIANCE EVENT — accept "COMPLIANCE_STATUS" (what compliance.py sends)
        # AND "COMPLIANCE_EVENT" (defensive alias).
        # Fields are at the TOP LEVEL of the event dict (not nested).
        elif event_type in _COMPLIANCE_TYPES:
            system["compliance"] = {
                "controls": ev.get("controls") or {},
                "compliance_score": ev.get("compliance_score"),
                "enforced": ev.get("enforced") or [],
                "timestamp": ev.get("timestamp") or time.time(),
            }
            print(f"[COMPLIANCE] stored for {agent_id} | "
                  f"score={system['compliance']['compliance_score']} | "
                  f"controls={list(system['compliance']['controls'].keys())}")

    return {"status": "ok", "received": len(evs)}

# ------------------ HEARTBEAT ------------------

@app.post("/api/v1/ingest/heartbeat")
async def heartbeat(payload: dict):

    agent_id = payload["agent_id"]

    system = systems.setdefault(agent_id, {
        "agent_id": agent_id,
        "username": None,
        "os": {},
        "usb": {},
        "vpn": {},
        "compliance": None,
        "auth": {"logins": 0, "last_user": None}
    })

    system["last_seen"] = time.time()
    system["os"] = payload.get("os", {})

    username = (payload.get("os") or {}).get("username")
    if username:
        system["username"] = username

    return {"status": "alive"}

# ------------------ READ APIs ------------------

@app.get("/api/v1/system/{agent_id}")
def get_system(agent_id: str):
    system = systems.get(agent_id)
    agent_events = events.get(agent_id, [])
    risk = compute_risk(agent_id, agent_events, system or {})
    return {
        "system": system,
        "events": list(agent_events),
        "risk_score": risk.get("risk_score"),
        "risk_level": risk.get("risk_level"),
        "risk_reasons": risk.get("reasons", []),
    }

@app.get("/api/v1/systems")
def get_all_systems():
    return list(systems.values())

# ------------------ Risk Engine ------------------

@app.get("/api/v1/risk/{agent_id}")
def get_risk(agent_id: str):
    agent_events = events.get(agent_id, [])
    system = systems.get(agent_id, {})
    return compute_risk(agent_id, agent_events, system)

@app.get("/api/v1/risk")
def get_all_risk():
    output = []
    for agent_id in systems:
        agent_events = events.get(agent_id, [])
        system = systems.get(agent_id, {})
        output.append(compute_risk(agent_id, agent_events, system))
    return output

# ------------------ Root Status ------------------

@app.get("/")
def root():
    summary = []
    for agent_id, system in systems.items():
        agent_events = events.get(agent_id, [])
        risk = compute_risk(agent_id, agent_events, system)
        summary.append({
            "agent_id": agent_id,
            "username": system.get("username") or (system.get("auth") or {}).get("last_user"),
            "last_seen": system.get("last_seen"),
            "events_count": len(agent_events),
            "risk": risk,
            "compliance_score": (system.get("compliance") or {}).get("compliance_score"),
        })
    return {"systems": summary}

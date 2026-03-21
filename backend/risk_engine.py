"""
AI-Augmented Risk Rule Engine for Insider Threat Detection

- Rule-based scoring
- Isolation Forest anomaly detection (per-agent)
- In-memory learning + auto retraining
"""

import time
from typing import Dict, Any, List
from sklearn.ensemble import IsolationForest

# ---------------- CONFIG ----------------

WINDOW_SEC = 600

THRESHOLD_MEDIUM = 30
THRESHOLD_HIGH = 60
THRESHOLD_CRITICAL = 80

BASELINE_WINDOW = 100
MIN_TRAIN_SIZE = 20

# ---------------- STORAGE ----------------

AGENT_HISTORY: Dict[str, List[List[float]]] = {}
AGENT_MODELS: Dict[str, IsolationForest] = {}

# ---------------- HELPERS ----------------

def _events_in_window(events, window_sec):
    if not events:
        return []
    now = time.time()
    cutoff = now - window_sec
    return [ev for ev in events if (ev.get("received_at") or ev.get("timestamp") or 0) >= cutoff]


def _extract_signals(evs, system):

    signals = {
        "file_writes": 0,
        "usb_active": False,
        "clipboard_events": 0,
        "process_count": 0,
        "upload_bytes": 0,
        "download_bytes": 0,
        "vpn_active": False,       # BUG 2 FIX: starts False, only set True by real events
        "session_duration": None,
        "compliance_score": None,
        "enforcement_triggered": False,
    }

    # BUG 2 FIX: track whether any VPN event was found in the window
    vpn_seen_in_events = False

    for ev in evs:
        try:
            etype = (ev.get("event_type") or "").upper()
            s = ev.get("summary") or {}

            if "FILE_ACTIVITY" in etype:
                signals["file_writes"] += s.get("write") or s.get("writes") or 0

            if "USB" in etype and "USB_REMOVE" not in etype:
                signals["usb_active"] = True

            if "CLIPBOARD" in etype:
                signals["clipboard_events"] += s.get("copy_events") or 0

            if "PROCESS" in etype:
                # BUG 1 FIX: use += (accumulate across events) not max()
                # max() was keeping a high value from one event and never resetting it,
                # causing the process spike rule to always fire once any batch arrived.
                try:
                    total = sum(int(v) for v in s.values() if isinstance(v, (int, float)))
                    signals["process_count"] += total   # ← was: max(signals[...], total)
                except Exception:
                    pass

            if "NETWORK" in etype:
                signals["upload_bytes"] += s.get("bytes_sent") or 0
                signals["download_bytes"] += s.get("bytes_received") or 0

            # BUG 2 FIX: read VPN from events in the window, not from stale system dict.
            # The agent sends a VPN_EVENT every time the VPN state changes.
            # We use the MOST RECENT VPN_EVENT in the window to determine current state.
            if "VPN" in etype:
                vpn_info = ev.get("vpn_info") or {}
                vpn_seen_in_events = True
                # Most recent event wins — events are appended in order, so last one is newest
                signals["vpn_active"] = vpn_info.get("vpn") is True

            if "USER_SESSION" in etype:
                signals["session_duration"] = s.get("duration_bucket")

            if "COMPLIANCE" in etype:
                if ev.get("compliance_score") is not None:
                    signals["compliance_score"] = ev.get("compliance_score")
                if ev.get("enforced"):
                    signals["enforcement_triggered"] = True

        except Exception:
            continue

    # BUG 2 FIX: only fall back to system["vpn"] if NO VPN event was seen in the
    # current 10-minute window. If we saw a VPN_EVENT (even vpn=False), trust it.
    # The old code always overwrote with system["vpn"] which is a cached dict that
    # only updates on new VPN_EVENT — so turning VPN off never reflected in the score.
    if not vpn_seen_in_events:
        signals["vpn_active"] = (system.get("vpn") or {}).get("vpn") is True

    # Compliance fallback — fine to keep as-is (no stale-override bug here)
    comp = system.get("compliance") or {}
    if signals["compliance_score"] is None:
        signals["compliance_score"] = comp.get("compliance_score")
    if not signals["enforcement_triggered"] and comp.get("enforced"):
        signals["enforcement_triggered"] = True

    return signals


# ---------------- FEATURES ----------------

def _get_features(signals):
    return [
        signals["file_writes"],
        int(signals["usb_active"]),
        signals["clipboard_events"],
        signals["process_count"],
        signals["upload_bytes"],
        signals["download_bytes"],
        int(signals["vpn_active"]),
    ]


# ---------------- MODEL ----------------

def _train_model(agent_id, history):
    if len(history) < MIN_TRAIN_SIZE:
        return

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(history)
    AGENT_MODELS[agent_id] = model


def _update_history(agent_id, features):
    history = AGENT_HISTORY.setdefault(agent_id, [])
    history.append(features)

    if len(history) > BASELINE_WINDOW:
        history.pop(0)

    if len(history) % 10 == 0:
        _train_model(agent_id, history)


def _ai_risk(agent_id, features):

    history = AGENT_HISTORY.get(agent_id, [])
    if len(history) < MIN_TRAIN_SIZE:
        return 0, []

    model = AGENT_MODELS.get(agent_id)
    if not model:
        _train_model(agent_id, history)
        model = AGENT_MODELS.get(agent_id)
        if not model:
            return 0, []

    prediction = model.predict([features])[0]  # -1 = anomaly
    score = model.decision_function([features])[0]

    reasons = []

    if prediction == -1:
        if score < -0.1:
            reasons.append("Strong anomaly detected (AI)")
            return 30, reasons
        else:
            reasons.append("Mild anomaly detected (AI)")
            return 15, reasons

    return 0, []


# ---------------- MAIN ENGINE ----------------

def compute_risk(agent_id, events, system):

    now = time.time()

    evs = _events_in_window(events or [], WINDOW_SEC)
    system = system or {}

    signals = _extract_signals(evs, system)

    # -------- RULE ENGINE --------
    risk_score = 0
    reasons = []

    if signals["file_writes"] > 50 and signals["usb_active"]:
        risk_score += 40
        reasons.append("High file activity")

    if signals["clipboard_events"] > 20 and signals["upload_bytes"] > signals["download_bytes"]:
        risk_score += 35
        reasons.append("Clipboard spike with outbound traffic")

    if signals["vpn_active"] and signals["file_writes"] > 50 and signals["upload_bytes"] > 0:
        risk_score += 30
        reasons.append("High file activity over VPN")

    # BUG 1 FIX: threshold raised to 200 to avoid always-firing.
    # process_count is now a SUM across the window so 120 (2*60) was
    # trivially exceeded by any normal session. 200 is a more meaningful spike.
    if signals["process_count"] > 200:
        risk_score += 20
        reasons.append("Process spike detected")

    if signals["upload_bytes"] > signals["download_bytes"] * 2:
        risk_score += 30
        reasons.append("High outbound traffic")

    if signals["compliance_score"] and signals["compliance_score"] < 60:
        risk_score += 20
        reasons.append("Low compliance score")

    # -------- AI ENGINE --------
    features = _get_features(signals)

    ai_score, ai_reasons = _ai_risk(agent_id, features)
    risk_score += ai_score
    reasons.extend(ai_reasons)

    # update history AFTER scoring
    _update_history(agent_id, features)

    # -------- FINAL --------
    risk_score = min(100, risk_score)

    if risk_score >= THRESHOLD_CRITICAL:
        level = "CRITICAL"
    elif risk_score >= THRESHOLD_HIGH:
        level = "HIGH"
    elif risk_score >= THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "agent_id": agent_id,
        "risk_score": risk_score,
        "risk_level": level,
        "reasons": reasons,
        "last_updated": now,
    }

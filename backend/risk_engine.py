"""
Risk Rule Engine for Insider Threat Detection.

Weighted, multi-signal risk scoring. Correlates events over a sliding time window.
Deterministic and explainable; no ML, no DB.
"""
import time
from typing import Dict, Any, List

# Sliding window (seconds)
WINDOW_SEC = 600  # 10 minutes

# Risk level thresholds
THRESHOLD_MEDIUM = 30
THRESHOLD_HIGH = 60
THRESHOLD_CRITICAL = 80


def _events_in_window(events: List[Dict[str, Any]], window_sec: float) -> List[Dict[str, Any]]:
    """Return events with received_at within the last window_sec."""
    if not events:
        return []
    now = time.time()
    cutoff = now - window_sec
    return [ev for ev in events if (ev.get("received_at") or ev.get("timestamp") or 0) >= cutoff]


def _extract_signals(evs: List[Dict[str, Any]], system: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract numeric/boolean signals from recent events and system state.
    Handles missing event types safely; uses defaults (0, False, None).
    """
    signals = {
        "file_writes": 0,
        "usb_active": False,
        "clipboard_events": 0,
        "process_count": 0,
        "upload_bytes": 0,
        "download_bytes": 0,
        "vpn_active": False,
        "session_duration": None,
        "compliance_score": None,
        "enforcement_triggered": False,
    }

    for ev in evs:
        try:
            etype = (ev.get("event_type") or "").upper()
            s = ev.get("summary") or {}

            # FILE_ACTIVITY / FILE_ACTIVITY_SUMMARY
            if "FILE_ACTIVITY" in etype:
                signals["file_writes"] += s.get("write") or s.get("writes") or 0

            # USB_EVENT, USB_REALTIME, USB_INSERT, USB_MODIFIED
            if "USB" in etype and "USB_REMOVE" not in etype:
                signals["usb_active"] = True

            # CLIPBOARD_ACTIVITY / CLIPBOARD_ACTIVITY_SUMMARY
            if "CLIPBOARD" in etype:
                signals["clipboard_events"] += s.get("copy_events") or 0

            # PROCESS_ACTIVITY / PROCESS_ACTIVITY_SUMMARY
            if "PROCESS" in etype:
                proc_summary = s if isinstance(s, dict) else {}
                total = sum(int(v) for v in (proc_summary.values() or []))
                signals["process_count"] += total

            # NETWORK_ACTIVITY / NETWORK_ACTIVITY_SUMMARY / NETWORK_VOLUME
            if "NETWORK" in etype:
                signals["upload_bytes"] += s.get("bytes_sent") or 0
                signals["download_bytes"] += s.get("bytes_received") or 0

            # VPN_EVENT
            if "VPN" in etype:
                vpn_info = ev.get("vpn_info") or {}
                signals["vpn_active"] = signals["vpn_active"] or (vpn_info.get("vpn") is True)

            # USER_SESSION_SUMMARY
            if "USER_SESSION" in etype:
                signals["session_duration"] = s.get("duration_bucket")

            # COMPLIANCE_STATUS / COMPLIANCE_EVENT
            if "COMPLIANCE_STATUS" in etype or "COMPLIANCE_EVENT" in etype:
                score = ev.get("compliance_score")
                if score is not None:
                    signals["compliance_score"] = score
                enforced = ev.get("enforced") or []
                if enforced:
                    signals["enforcement_triggered"] = True

            # COMPLIANCE_ENFORCED
            if "COMPLIANCE_ENFORCED" in etype:
                signals["enforcement_triggered"] = True

        except Exception:
            continue

    # VPN from system state (heartbeat/ingest)
    if not signals["vpn_active"]:
        vpn_info = system.get("vpn") or {}
        signals["vpn_active"] = vpn_info.get("vpn") is True

    # Compliance from system state
    if signals["compliance_score"] is None:
        comp = system.get("compliance") or {}
        signals["compliance_score"] = comp.get("compliance_score")
    if not signals["enforcement_triggered"]:
        comp = system.get("compliance") or {}
        if comp.get("enforced"):
            signals["enforcement_triggered"] = True

    return signals


def compute_risk(
    agent_id: str,
    events: List[Dict[str, Any]],
    system: Dict[str, Any],
    window_sec: float = WINDOW_SEC,
) -> Dict[str, Any]:
    """
    Compute weighted risk score and level for one agent from events in the sliding window.
    Returns agent_id, risk_score, risk_level, reasons, last_updated.
    """
    now = time.time()
    evs = _events_in_window(events or [], window_sec)
    system = system or {}

    signals = _extract_signals(evs, system)
    risk_score = 0
    reasons: List[str] = []

    # --- RULE: File burst + USB ---
    if signals["file_writes"] > 50 and signals["usb_active"]:
        risk_score += 40
        reasons.append("High file activity with USB usage (possible data exfiltration)")

    # --- RULE: Clipboard + Network upload ---
    if signals["clipboard_events"] > 20 and signals["upload_bytes"] > signals["download_bytes"]:
        risk_score += 35
        reasons.append("Clipboard spike with high outbound network traffic")

    # --- RULE: VPN + File activity ---
    if signals["vpn_active"] and signals["file_writes"] > 30:
        risk_score += 30
        reasons.append("High file activity over VPN connection")

    # --- RULE: Process spike ---
    if signals["process_count"] > 20:
        risk_score += 20
        reasons.append("Unusual number of processes started")

    # --- RULE: Network exfiltration ---
    if signals["download_bytes"] > 0 and signals["upload_bytes"] > signals["download_bytes"] * 2:
        risk_score += 30
        reasons.append("Unusually high outbound network traffic")
    elif signals["download_bytes"] == 0 and signals["upload_bytes"] > 0:
        risk_score += 30
        reasons.append("Unusually high outbound network traffic")

    # --- RULE: Compliance violation + activity ---
    comp_score = signals["compliance_score"]
    if comp_score is not None and comp_score < 60 and signals["file_writes"] > 30:
        risk_score += 35
        reasons.append("High activity on non-compliant system")

    # --- RULE: Enforcement triggered ---
    if signals["enforcement_triggered"]:
        risk_score += 30
        reasons.append("System automatically enforced security policy")

    # --- RULE: Long session activity ---
    session_dur = signals["session_duration"]
    long_session = session_dur in (">120", "120+")
    if long_session and signals["file_writes"] > 30:
        risk_score += 20
        reasons.append("High activity during extended session")

    # --- RULE: Multi-signal correlation ---
    if (
        signals["usb_active"]
        and signals["clipboard_events"] > 10
        and signals["upload_bytes"] > signals["download_bytes"]
    ):
        risk_score += 25
        reasons.append("Multi-channel data exfiltration pattern detected")

    # --- Risk level ---
    risk_score = min(100, risk_score)
    if risk_score >= THRESHOLD_CRITICAL:
        risk_level = "CRITICAL"
    elif risk_score >= THRESHOLD_HIGH:
        risk_level = "HIGH"
    elif risk_score >= THRESHOLD_MEDIUM:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "agent_id": agent_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "last_updated": now,
    }

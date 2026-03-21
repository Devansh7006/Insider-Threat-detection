# agent/vpn_api.py
"""
Local VPN Analyzer API used by the agent.
Endpoint:
  GET /analyze  -> returns { ipv4, ipv6, country, city, isp, vpn, blacklisted, note? }
"""

import os
import requests
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

# ---------- Configuration ----------
PROVIDERS = [
    "https://ipapi.co/json/",
    "https://ipinfo.io/json",
    "http://ip-api.com/json/"   # http allowed; keep last as fallback
]

VPN_KEYWORDS = [
    "vpn", "proxy", "hosting", "datacenter",
    "amazon", "aws", "google", "azure",
    "digitalocean", "cloudflare", "linode", "ovh",
    "hetzner", "cloud", "edge", "hosting"
]

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")  # optional, keep empty if not available
ABUSE_SCORE_THRESHOLD = 50

# timeouts (seconds)
PROVIDER_TIMEOUT = 4.0
ABUSE_TIMEOUT = 6.0

app = FastAPI(title="Agent VPN Analyzer", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # keep permissive for local usage; lock down in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Helpers ----------
def fetch_json(url: str, timeout: float = PROVIDER_TIMEOUT) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def fetch_ip_data() -> Optional[Dict[str, Optional[str]]]:
    """
    Try multiple providers and return first valid public IP + geo/isp details.
    Normalizes to keys: ip, country, city, isp
    """
    for url in PROVIDERS:
        j = fetch_json(url)
        if not j:
            continue

        # providers differ in field names
        ip = j.get("ip") or j.get("query") or j.get("IP") or j.get("ip_address")
        if not ip:
            # ip-api returns 'query' field; ipinfo sometimes uses 'ip'
            continue

        country = j.get("country_name") or j.get("country") or j.get("countryCode")
        city = j.get("city")
        isp = j.get("org") or j.get("isp") or j.get("organization") or j.get("company")

        return {"ip": ip, "country": country, "city": city, "isp": isp}
    return None

def split_ipv4_ipv6(ip: str) -> Dict[str, Optional[str]]:
    if not ip:
        return {"ipv4": None, "ipv6": None}
    return {"ipv4": None if ":" in ip else ip, "ipv6": ip if ":" in ip else None}

def is_vpn_like(isp: Optional[str]) -> bool:
    if not isp:
        return False
    low = isp.lower()
    return any(k in low for k in VPN_KEYWORDS)

def check_abuseipdb(ip: str) -> Optional[bool]:
    """
    Returns True/False if AbuseIPDB check was performed, else None.
    Requires ABUSEIPDB_KEY env var.
    """
    key = ABUSEIPDB_KEY
    if not key:
        return None
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=ABUSE_TIMEOUT)
        r.raise_for_status()
        payload = r.json()
        score = payload.get("data", {}).get("abuseConfidenceScore")
        if score is None:
            return None
        return int(score) >= ABUSE_SCORE_THRESHOLD
    except Exception:
        return None

# ---------- Routes ----------
@app.get("/")
def root():
    return {"status": "ok", "note": "VPN Analyzer API", "abuseipdb_configured": bool(ABUSEIPDB_KEY)}

@app.get("/analyze")
def analyze(request: Request):
    """
    Returns:
    {
      "ipv4": "...", "ipv6": "...",
      "country": "...", "city": "...", "isp": "...",
      "vpn": true|false,
      "blacklisted": true|false|null,
      "note": Optional error note
    }
    """
    result = {
        "ipv4": None,
        "ipv6": None,
        "country": None,
        "city": None,
        "isp": None,
        "vpn": False,
        "blacklisted": None
    }

    ip_info = fetch_ip_data()
    if not ip_info:
        result["note"] = "unable-to-fetch-ip"
        return result

    ip = ip_info.get("ip")
    parts = split_ipv4_ipv6(ip)
    isp = ip_info.get("isp")

    result.update({
        "ipv4": parts["ipv4"],
        "ipv6": parts["ipv6"],
        "country": ip_info.get("country"),
        "city": ip_info.get("city"),
        "isp": isp
    })

    # simple heuristic: ISP string contains known VPN/cloud keywords
    result["vpn"] = bool(is_vpn_like(isp))

    # optional AbuseIPDB check
    blacklisted = None
    try:
        if ip and ABUSEIPDB_KEY:
            blacklisted = check_abuseipdb(ip)
    except Exception:
        blacklisted = None
    result["blacklisted"] = blacklisted

    return result

# ---------- Run helper ----------
if __name__ == "__main__":
    # When run as module: `python -m agent.vpn_api`
    # This prints message then runs uvicorn on 127.0.0.1:8001 (agent expects that).
    import uvicorn
    print("Starting agent.vpn_api on http://127.0.0.1:8001")
    uvicorn.run("agent.vpn_api:app", host="127.0.0.1", port=8001, log_level="warning", reload=False)

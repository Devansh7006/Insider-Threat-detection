# ITD — Insider Threat Detection System

Host-based monitoring that scores **insider-risk behavior** on endpoints in near real time. A Python **agent** collects activity, a **FastAPI** backend applies **explainable rules** plus **per-agent anomaly detection** (Isolation Forest), and a **React** dashboard surfaces alerts and context.

> **Scope:** Risk signaling and analyst triage — not a standalone proof of malicious intent.

---

## For Documentation

- **Course / submission write-up:** [TECHNICAL_DOCUMENTATION.md](./PS3_TECHNICAL_DOCUMENTATION.md) — architecture, privacy notes, evaluation guidance.
- **Rule descriptions (supplementary):** [backend/RISK_RULES.md](./backend/RISK_RULES.md) — compare with `backend/risk_engine.py` for the exact implementation.

---

## What it does

| Layer | Role |
|--------|------|
| **Agent** | Observes file, USB, VPN, clipboard, process, network, session, and compliance-related signals; sends structured JSON events and heartbeats. |
| **Backend** | Ingests events, aggregates a sliding time window, computes `risk_score` / `risk_level` with human-readable `reasons`, optional DB persistence. |
| **Dashboard** | Lists endpoints, shows risk, details, and charts; refreshes via HTTP polling. |

**Design goals:** correlate weak signals into stronger indicators, keep outputs **interpretable** (rules + bounded ML contribution), stay lightweight enough to demo and extend.

---

## Stack

- **Backend:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, scikit-learn (Isolation Forest), PostgreSQL (via `DATABASE_URL`).
- **Agent:** Python (`agent/`).
- **Frontend:** React 18, Vite 5, Recharts / Chart.js.

---

## Prerequisites

- **Python 3.10+** and **Node.js 18+** (for the dashboard).
- **PostgreSQL** for persistent event storage (recommended). The app initializes an `events` table on startup.

---

## Environment

Create a `.env` in the project root (or set variables in your shell):

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | SQLAlchemy URL, e.g. `postgresql+psycopg2://user:pass@localhost:5432/itd` |
| `VITE_BACKEND_URL` | (Frontend build/dev) Base URL of the API, e.g. `http://127.0.0.1:8000` |

Agent-related (optional):

| Variable | Purpose |
|----------|---------|
| `ITD_BACKEND` | API base URL for the agent (default `http://127.0.0.1:8000`) |
| `ITD_AGENT_ID` | Stable id for this endpoint |
| `ITD_HEARTBEAT_INTERVAL` | Heartbeat seconds (default `10`) |

---

## Quick start

### 1. Python dependencies

```powershell
cd path\to\Insider-Threat-detection-main
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Install agent extras if needed:

```powershell
pip install -r agent\requirements.txt
```

### 2. Start the API

From the **repository root** (required because `backend` is a package with relative imports):

```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

- API: [http://127.0.0.1:8000](http://127.0.0.1:8000)  
- OpenAPI docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 3. Start the dashboard

```powershell
cd frontend
npm install
npm run dev
```

- UI: [http://localhost:5173](http://localhost:5173)  
- Point `VITE_BACKEND_URL` at your API if it is not on localhost.

### 4. Run the agent

In another terminal (with venv activated):

```powershell
cd path\to\Insider-Threat-detection-main
python -m agent
```

Optional **VPN analyzer** microservice (if you use VPN features):

```powershell
python -m agent.vpn_api
```

Listens on [http://127.0.0.1:8001](http://127.0.0.1:8001) by default.

### 5. Optional: run multiple processes from the repo root

If you use the root `package.json` scripts (install root devDependencies first: `npm install`):

```powershell
npm run backend    # expects venv at backend\venv per script — adjust if your venv is at repo root
npm run frontend
```

Edit `package.json` scripts if your virtualenv lives at the repo root instead of `backend/venv`.

---

## Verify

```powershell
curl http://127.0.0.1:8000/api/v1/systems
curl http://127.0.0.1:8000/api/v1/risk
```

If the VPN service is running:

```powershell
curl http://127.0.0.1:8001/analyze
```

---

## API overview

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/ingest` | Ingest batched agent events |
| `POST` | `/api/v1/ingest/heartbeat` | Agent heartbeat |
| `GET` | `/api/v1/systems` | Active systems |
| `GET` | `/api/v1/system/{agent_id}` | System, events, risk |
| `GET` | `/api/v1/risk` | Risk for all agents |
| `GET` | `/api/v1/risk/{agent_id}` | Risk for one agent |

---



## Repository layout

```
Insider-Threat-detection-main/
├── backend/           # FastAPI app, risk engine, database
├── agent/             # Endpoint collectors and sender
├── frontend/          # React (Vite) dashboard
├── requirements.txt   # Backend + API dependencies
├── PS3_TECHNICAL_DOCUMENTATION.md
└── README.md
```

---

## Production notes

- Serve the API behind **HTTPS**; restrict **CORS** (`backend/main.py` currently allows all origins for development).
- Use managed PostgreSQL and secrets injection for `DATABASE_URL`.
- Replace client-side demo login with your organization’s authentication if required.

---

## License

Add a `LICENSE` file if you distribute this project publicly.

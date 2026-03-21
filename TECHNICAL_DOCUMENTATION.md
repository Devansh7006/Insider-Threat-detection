# PS3: AI-Powered Insider Threat Detection System  
## Technical Documentation & Submission Package

**Project name:** ITD (Insider Threat Detection)  
**Scope:** End-to-end host-based monitoring with a detection engine, data ingestion pipeline, and security dashboard.

This document aligns the coursework problem statement with the delivered system: what was built, how it works, architectural decisions, privacy considerations, and how to run it.

---

## 1. Problem statement alignment

| Requirement | How this project addresses it |
|-------------|--------------------------------|
| **Detection engine** for anomalous / high-risk behavior | Hybrid **rule-based scoring** plus **per-agent Isolation Forest** anomaly detection over engineered features (see §4). |
| **Dashboard** with alerts, trends, summary statistics | **React (Vite)** dashboard: agent list, risk levels, reasons, activity detail, charts; polling-based refresh for near–real-time views (see §6). |
| **Data processing module** turning raw activity into structured data | **Endpoint agent** normalizes OS-level signals into **JSON events**; **FastAPI ingest** validates and stores structured payloads (see §5). |
| **End-to-end unified system** | **Agent → Backend (ingest + risk APIs) → Database persistence → Dashboard** as one integrated prototype. |

**Design stance (evaluation philosophy):** Insider threat is fundamentally **contextual**: “normal” differs by user, role, and organization. This implementation therefore emphasizes **online, per-entity behavioral baselines** (per `agent_id`) and explainable rules, rather than a single offline model trained on one static public corpus. That choice targets **operational fit** and **interpretability** for security teams; it is documented here as an explicit architectural decision (§4.3).

---

## 2. System objectives (course objectives → implementation)

### 2.1 Detection engine (precision/recall balance)

- **Deterministic rules** encode security-relevant combinations (e.g., high file activity with USB, clipboard spikes with outbound-heavy network, VPN plus file burst, compliance enforcement). These improve **interpretability** and reduce opaque alerts.
- **Isolation Forest** (`scikit-learn`) operates on a **fixed feature vector per time window**, with **per-agent history** and periodic refit. Anomalies add a bounded score contribution with explicit “AI” reasons.
- **Thresholds** map cumulative score to `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` for actionable triage.

*Note:* Classical **precision/recall/F1** require a labeled dataset and a fixed prediction task. This prototype is optimized for **live risk scoring**; §9 describes how performance can be discussed and extended.

### 2.2 Visualization and insight platform

- Lightweight **web UI** (not Streamlit/Dash; React is equivalent for the “lightweight dashboard” requirement).
- **Alerts:** risk level + textual `reasons` per agent.
- **Trends / summaries:** event-derived stats in the detail view (e.g., rolling window), endpoint counts, last sync time.

### 2.3 Dataset / log processing

- **Source:** Host telemetry (file, USB, clipboard, process, network, VPN, user session, compliance), not generic third-party log files.
- **Processing:** Events are **structured at the agent** (typed `event_type`, `summary`, timestamps) and **ingested** as JSON; the backend aggregates them for risk computation and optional persistence.

---

## 3. High-level architecture

```
┌─────────────────┐     HTTPS/HTTP      ┌──────────────────┐     ┌─────────────┐
│  Endpoint Agent │ ──────────────────► │  FastAPI Backend │ ──► │  PostgreSQL │
│  (Python)       │   /api/v1/ingest    │  risk + REST API │     │  (optional) │
└─────────────────┘                     └────────┬─────────┘     └─────────────┘
                                                 │
                                                 │ REST (poll)
                                                 ▼
                                        ┌──────────────────┐
                                        │  React Dashboard │
                                        │  (Vite)          │
                                        └───────────────────┘
```

- **Agent:** Collects activity, sends batched events and heartbeats to the backend.
- **Backend:** In-memory state for live aggregation; **SQLAlchemy** persistence for events (`DATABASE_URL`).
- **Frontend:** Configurable backend URL via `VITE_BACKEND_URL` (default may point to a hosted API for demos).

---

## 4. Detection engine

### 4.1 Location and dependencies

- **Module:** `backend/risk_engine.py`
- **Libraries:** `sklearn.ensemble.IsolationForest` plus custom signal extraction and rule logic.

### 4.2 Feature extraction (sliding window)

- **Window:** Approximately **10 minutes** (`WINDOW_SEC = 600`) of recent events per agent.
- **Signals** aggregated include (non-exhaustive): file write counts, USB activity flag, clipboard events, process-related counts, upload/download bytes, VPN active flag; compliance fields are incorporated from events or system state where available.
- **Feature vector** (for the anomaly detector) includes numeric/boolean components derived from those signals (e.g., file writes, USB flag, clipboard count, process count, upload/download bytes, VPN flag).

### 4.3 Rule engine + AI layer

1. **Rules** add weighted points when conditions match (examples implemented in code): file + USB correlation, clipboard + outbound traffic, VPN + file activity, process spike, upload-heavy vs download, low compliance score, enforcement triggered.
2. **Isolation Forest:** Trained per `agent_id` once enough history exists (`MIN_TRAIN_SIZE`); **contamination** hyperparameter controls expected anomaly rate. Anomaly predictions contribute additional score and reasons (“Mild/Strong anomaly detected (AI)”).
3. **Output:** `risk_score` (capped), `risk_level`, `reasons`, `last_updated`.

### 4.4 Why per-agent baselines (design rationale)

- **Role heterogeneity:** One global model trained offline can mis-rank benign power users versus subtle insiders.
- **Operational grounding:** The engine continuously adapts to **each endpoint’s** recent behavior, which matches how SOCs often reason about **deviation from local norm**.
- **Explainability:** Rules provide human-readable causes; the anomaly layer adds a statistical second opinion without replacing transparency.
**Why Real-Time Behavioral Learning > Static Datasets:** Traditional approaches rely on datasets such as the CMU Insider Threat Dataset.

**Limitations of Dataset-Based Systems:** Static assumptions of behavior, No personalization, Cannot detect new attack patterns, Not real-time. **Advantages of Dracarys:** Adaptive Learning Continuously updates user behavior baseline Unsupervised AI, No dependency on labeled datasets, Real-Time Detection, Detects threats instantly, Personalization, Different baseline for each user Explainability Combines AI + rule-based reasoning

**Note:** The system is dataset-compatible and can ingest structured datasets if required. ✔ However, real-time adaptive detection better reflects modern cybersecurity systems.

---

## 5. Data processing pipeline

### 5.1 Agent-side structuring

- Collectors under `agent/collectors/` (e.g., Windows-focused modules) produce **typed events** with consistent fields suitable for ingestion.
- **Heartbeat** and **ingest** endpoints keep the backend aware of **last_seen** and OS/user context.

### 5.2 Backend ingest

- **Endpoint:** `POST /api/v1/ingest` — accepts `agent_id` and `events[]`; stamps `received_at`, updates per-agent state (USB, VPN, auth, compliance), appends to in-memory event lists, and persists via `save_event`.
- **Heartbeat:** `POST /api/v1/ingest/heartbeat` — liveness and OS snapshot.

### 5.3 Storage model

- **Table:** `events` with `agent_id`, `event_type`, JSON `data`, `created_at` (`backend/database.py`).
- **Configuration:** `DATABASE_URL` in environment (e.g., PostgreSQL).

---

## 6. Dashboard (visualization platform)

### 6.1 Technology

- **React** + **Vite**, styling tuned for a security-operations aesthetic.
- **Charts:** e.g., **Recharts** (area charts in system detail), plus Chart.js components where used.

### 6.2 Capabilities

- **Agent list** with selection and risk mapping.
- **System detail** for a chosen `agent_id`: risk score/level, reasons, compliance and OS resolution from events, periodic refresh.
- **Near–real-time behavior:** HTTP polling (dashboard and detail intervals); WebSocket helpers exist in the client but streaming is not required for the core demo.

### 6.3 Authentication note

- Client-side login state (e.g., `localStorage`) for UI gating; production deployments should replace with proper identity federation if required.

---

## 7. API reference (core)

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/ingest` | Submit agent events |
| `POST` | `/api/v1/ingest/heartbeat` | Agent heartbeat |
| `GET` | `/api/v1/systems` | List active systems |
| `GET` | `/api/v1/system/{agent_id}` | System + events + embedded risk |
| `GET` | `/api/v1/risk` | Risk summary for all known agents |
| `GET` | `/api/v1/risk/{agent_id}` | Risk for one agent |
| `GET` | `/` | Aggregated JSON overview |

---

## 8. Privacy and security measures

| Measure | Implementation / guidance |
|---------|-----------------------------|
| **Transport** | Use **HTTPS** in production for agent→API and browser→API; development may use HTTP on localhost. |
| **Secrets** | Store `DATABASE_URL` and API URLs in **environment variables**, not in source control. |
| **Data minimization** | Design focuses on **activity metadata** (counts, types, sizes) rather than file contents for detection. |
| **Pseudonymization** | `agent_id` can be treated as an endpoint identifier; user names may appear in telemetry — production deployments should align with policy (hashing/redaction at source if required). |
| **Encryption at rest** | Rely on **database and disk encryption** provided by the hosting provider; application-level AES for JSON blobs is optional hardening. |

*Honest scope:* This repository demonstrates **architecture and hooks**; full enterprise anonymization and key management should be specified for a regulated environment.

---

## 9. Scalability and performance

- **Current prototype:** In-memory per-agent event buffers suit **moderate** event rates and demo fleets. Very large deployments would require **stream processing**, **event retention policies**, and **horizontal scaling** of stateless API nodes with a shared store (e.g., Kafka + DB + cache)—listed as future work.
- **Model cost:** Isolation Forest training is periodic and bounded by per-agent history length (`BASELINE_WINDOW`).

---


## 10. Setup instructions

### 10.1 Backend

1. Python 3.10+ recommended.  
2. Create a virtual environment and install dependencies:  
   `pip install -r requirements.txt` (from project root; see also `backend/requirements.txt` if split).  
3. Set `DATABASE_URL` for PostgreSQL (SQLAlchemy).  
4. From the package root, run Uvicorn with the app module path used in your layout (example):  
   `uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload`  
   Adjust if your entrypoint differs (`main.py` lives under `backend/`).

### 10.2 Agent

- Configure `agent/config.yaml` / environment (`ITD_BACKEND`, `ITD_AGENT_ID`, etc.).  
- Run the agent module as documented in `README.md` (e.g., `python -m agent`).  
- Optional: `python -m agent.vpn_api` for the VPN analyzer microservice on port `8001` if used.

### 10.3 Frontend

1. `cd frontend`  
2. `npm install`  
3. `npm run dev` (default dev server, often `http://localhost:5173`)  
4. Set `VITE_BACKEND_URL` to your API base URL for production or remote backends.

---

## 11. Repository layout (summary)

- `backend/` — FastAPI app, risk engine, database layer.  
- `agent/` — Endpoint collectors, heartbeat, sender, VPN helper.  
- `frontend/` — React dashboard.  
- `README.md` — Quick start.  
- `backend/RISK_RULES.md` — Supplementary rule descriptions (verify against `risk_engine.py` for exact implemented thresholds).

---



## 12. Intellectual honesty & originality

- Core orchestration, rules, and integration are **implemented for this project**.  
- **scikit-learn** Isolation Forest is a **standard library** component (not a copied end-to-end external solution).  
- The system **does not** claim proof of malicious intent; it flags **risk** for analyst review.

---

## 13. References (non-code)

- Scikit-learn: Isolation Forest for unsupervised anomaly detection.  
- Insider threat programs commonly combine **policy rules** with **behavioral analytics**; this project mirrors that pattern in a lightweight form.

---

**Document version:** 1.0  
**Prepared for:** PS3 submission (Insider Threat Detection System)

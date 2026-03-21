🛡️ ITD — Insider Threat Detection System

ITD is a host-based, real-time Insider Threat Detection system designed to identify risky behavioral patterns on endpoint machines using deterministic, explainable rules.

The system combines a local agent, a FastAPI backend, and a React dashboard to monitor activity such as file operations, USB usage, VPN behavior, clipboard activity, suspicious processes, and network patterns — and correlates them into meaningful risk levels.

⚠️ This project focuses on risk signaling, not proving malicious intent.

🎯 Objectives

Detect potential insider threat behavior in near real time

Correlate multiple weak signals into stronger risk indicators

Maintain full explainability (no black-box ML)

Keep architecture lightweight and research-friendly


1️⃣ Start the Backend (FastAPI)
Windows (PowerShell):

1) venv\Scripts\Activate.ps1
   
Step 4: Install Python dependencies
1) pip install -r requirements.txt

Start backend server:

1) cd D:/ITD
2) uvicorn main:app --host 127.0.0.1 --port 8000 --reload


📍 Backend running at:
http://127.0.0.1:8000

2️⃣ Start the Agent VPN Analyzer (Local Microservice)

1) cd D:/ITD
2) python -m agent.vpn_api

📍 VPN Analyzer running at:
http://127.0.0.1:8001

3️⃣ Start the Frontend

1) cd frontend
2) npm run dev



📡 Agent will:

Detect OS, USB, VPN, clipboard, file activity

Send events to backend

Send heartbeat every few seconds

⚠️ If main.py is not present, start the agent module directly:

python -m agent

4️⃣ Start the Frontend Dashboard (React)
Step 1: Open another terminal
cd frontend

Step 2: Install dependencies (first time only)
npm install

Step 3: Start development server
npm run dev


📍 Dashboard available at:

http://localhost:5173

5️⃣ Verify Everything Is Running
Backend Health
curl http://127.0.0.1:8000/api/v1/systems

Risk Engine
curl http://127.0.0.1:8000/api/v1/risk

VPN Analyzer
curl http://127.0.0.1:8001/analyze

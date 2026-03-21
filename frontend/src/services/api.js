const API_BASE = "https://insider-threat-detection-szmm.onrender.com";

// ------------------ SYSTEMS ------------------

export async function fetchSystems() {
  const res = await fetch(`${API_BASE}/api/v1/systems`);
  if (!res.ok) {
    throw new Error("Failed to fetch systems");
  }
  return res.json();
}

export async function fetchAgentSystem(agentId) {
  const res = await fetch(`${API_BASE}/api/v1/system/${agentId}`);
  if (!res.ok) {
    throw new Error("Failed to fetch agent system");
  }
  return res.json();
}

// ------------------ RISK ------------------

export async function fetchAllRisk() {
  const res = await fetch(`${API_BASE}/api/v1/risk`);
  if (!res.ok) {
    throw new Error("Failed to fetch risk data");
  }
  return res.json();
}

export async function fetchAgentRisk(agentId) {
  const res = await fetch(`${API_BASE}/api/v1/risk/${agentId}`);
  if (!res.ok) {
    throw new Error("Failed to fetch agent risk");
  }
  return res.json();
}
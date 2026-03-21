// frontend/src/api/system.js
export async function fetchSystem(agentId) {
  const url = `http://127.0.0.1:8000/api/v1/system/${encodeURIComponent(agentId)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return res.json();
}

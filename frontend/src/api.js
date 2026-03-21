// src/api.js
const BACKEND =
  (import.meta.env.VITE_BACKEND_URL ||
   "https://insider-threat-detection-szmm.onrender.com"
  ).replace(/\/$/, "");

const NO_CACHE = { cache: "no-store", headers: { "Cache-Control": "no-cache", Pragma: "no-cache" } };

function urlWithStamp(path) {
  return `${BACKEND}${path}${path.includes("?") ? "&" : "?"}_=${Date.now()}`;
}

export const API = {
  listSystems: async () => {
    const r = await fetch(urlWithStamp("/api/v1/systems"), NO_CACHE);
    if (!r.ok) throw new Error("listSystems failed");
    return await r.json();
  },
  getSystem: async (id) => {
    const r = await fetch(urlWithStamp(`/api/v1/system/${encodeURIComponent(id)}`), NO_CACHE);
    if (!r.ok) throw new Error("getSystem failed");
    return await r.json();
  },
  getAllRisk: async () => {
    const r = await fetch(urlWithStamp("/api/v1/risk"), NO_CACHE);
    if (!r.ok) throw new Error("getAllRisk failed");
    return await r.json();
  },
  getRisk: async (agentId) => {
    const r = await fetch(urlWithStamp(`/api/v1/risk/${encodeURIComponent(agentId)}`), NO_CACHE);
    if (!r.ok) throw new Error("getRisk failed");
    return await r.json();
  },
};

export function createWS(onMessage) {
  const url = (location.protocol === "https:" ? "wss" : "ws") + "://" + location.hostname + ":8000/ws";
  const ws = new WebSocket(url);
  ws.onopen = () => console.info("ws open");
  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)); } catch (err) {}
  };
  ws.onclose = () => console.info("ws closed");
  ws.onerror = (e) => console.error("ws error", e);
  return ws;
}

import React, { useEffect, useState } from "react";
import { API } from "../api";

export default function AgentSelect({ onSelectAgent, onLogout }) {
  const [systems, setSystems] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    API.listSystems()
      .then((res) => {
        const list = Array.isArray(res) ? res : res?.systems || [];
        setSystems(list);
      })
      .catch((err) => console.error("Failed to load systems", err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{
      minHeight: "100vh",
      width: "100vw",
      backgroundColor: "#1a0b2e", // Dark purple base
      backgroundImage: "radial-gradient(circle at 50% 50%, #2a0845 0%, #050a14 100%)",
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      color: "#fff",
      fontFamily: "'Rajdhani', 'Share Tech Mono', sans-serif"
    }}>
      <div style={{
        background: "rgba(20, 10, 30, 0.6)",
        backdropFilter: "blur(15px)",
        border: "1px solid rgba(255, 0, 255, 0.1)",
        borderRadius: "16px",
        padding: "3rem",
        width: "800px",
        maxWidth: "90vw",
        boxShadow: "0 20px 50px rgba(0,0,0,0.5)"
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div>
            <h1 style={{ margin: 0, fontSize: "2rem", letterSpacing: "1px" }}>Active Agents</h1>
            <p style={{ color: "rgba(255,255,255,0.6)", fontSize: "0.9rem", margin: "5px 0" }}>Endpoints currently reporting telemetry</p>
            <h2 style={{ fontSize: "1.5rem", marginTop: "10px", color: "#e0e0e0" }}>Someone's system is always screaming.</h2>
          </div>
          <button 
            onClick={onLogout}
            style={{ background: "transparent", border: "1px solid #ff003c", color: "#ff003c", padding: "0.4rem 1rem", cursor: "pointer", borderRadius: "4px" }}
          >
            LOGOUT
          </button>
        </div>

        <div style={{ marginTop: "2rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
          {loading ? (
            <div style={{ color: "#00f0ff", fontFamily: "monospace" }}>Scanning network for endpoints...</div>
          ) : systems.length === 0 ? (
            <div style={{ color: "#ff003c", fontFamily: "monospace" }}>NO ENDPOINTS DETECTED</div>
          ) : (
            systems.map((sys) => {
              const agentNum = sys.agent_id.split('-')[1] || sys.agent_id;
              
              return (
                <div 
                  key={sys.agent_id}
                  onClick={() => onSelectAgent(sys.agent_id)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "1.5rem",
                    padding: "1.5rem",
                    border: "1px solid rgba(255,0,255,0.2)",
                    borderRadius: "12px",
                    background: "rgba(0,0,0,0.3)",
                    cursor: "pointer",
                    transition: "all 0.3s ease"
                  }}
                  onMouseOver={(e) => {
                    e.currentTarget.style.background = "rgba(189, 0, 255, 0.1)";
                    e.currentTarget.style.borderColor = "rgba(189, 0, 255, 0.5)";
                  }}
                  onMouseOut={(e) => {
                    e.currentTarget.style.background = "rgba(0,0,0,0.3)";
                    e.currentTarget.style.borderColor = "rgba(255,0,255,0.2)";
                  }}
                >
                  <div style={{ 
                    width: "50px", height: "50px", borderRadius: "50%", 
                    background: "rgba(189, 0, 255, 0.2)", color: "#e0aaff",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontWeight: "bold", border: "1px solid #bd00ff"
                  }}>
                    {agentNum}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: "1.2rem", fontWeight: "bold" }}>{sys.agent_id.toUpperCase()}</div>
                    <div style={{ color: "rgba(255,255,255,0.5)", fontSize: "0.9rem" }}>Administrator</div>
                  </div>
                  <div style={{ color: "#00f0ff", fontSize: "0.9rem", fontFamily: "monospace" }}>
                    View Dashboard &rarr;
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  );
}
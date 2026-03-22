import { useState, useEffect } from "react";
import Dashboard from "./Pages/Dashboard";
import AgentSelect from "./Pages/AgentSelect";
import "./styles/login.css";

/* ================= LOGIN COMPONENT ================= */

function Login({ onSuccess }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    await new Promise((r) => setTimeout(r, 400));

    if (username === "devansh" && password === "goyal") {
      const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

localStorage.setItem(
  "dikoryx_session",
  JSON.stringify({
    user: "admin",
    expires: expiry
  })
);
      onSuccess("admin");
      return;
    }
    if (username === "aditya" && password === "dagar") {
      const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

localStorage.setItem(
  "dikoryx_session",
  JSON.stringify({
    user: "admin",
    expires: expiry
  })
);
      onSuccess("admin");
      return;
    }

    setLoading(false);
    setPassword("");
    setError("Authentication failed. Verify credentials.");
  };

  return (
    <div className="dkx-login-page">
      <div className="dkx-glass-card">
        <div className="dkx-avatar">
          <svg width="40" height="40" viewBox="0 0 24 24">
            <circle cx="12" cy="8" r="4" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M4 20c1.5-4 14.5-4 16 0" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        </div>

        <h1 className="dkx-title">Dikoryx</h1>
        <p className="dkx-sub">Username:devansh Password:goyal</p>

        <form className="dkx-form" onSubmit={handleSubmit}>
          <input
            className="dkx-input"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />

          <div className="dkx-password-row">
            <input
              className="dkx-input"
              type={showPwd ? "text" : "password"}
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="button"
              className="dkx-eye-btn"
              onClick={() => setShowPwd((s) => !s)}
            >
              {showPwd ? "🙈" : "👁️"}
            </button>
          </div>

          {error && <div className="dkx-error-text">{error}</div>}

          <button className="dkx-btn-primary" disabled={loading}>
            {loading ? "Authenticating…" : "LOGIN"}
          </button>
        </form>
      </div>
    </div>
  );
}

/* ================= APP CONTROLLER ================= */

export default function App() {
  const [user, setUser] = useState(() => {
  const stored = localStorage.getItem("dikoryx_session");
  if (!stored) return null;

  try {
    const session = JSON.parse(stored);

    if (Date.now() > session.expires) {
      localStorage.removeItem("dikoryx_session");
      return null;
    }

    return session.user;
  } catch {
    return null;
  }
});
  const [agentId, setAgentId] = useState(null);
  const [activeAgents, setActiveAgents] = useState([]);
  const [loadingAgents, setLoadingAgents] = useState(true);

  

  // 🔄 Fetch active agents from backend
  useEffect(() => {
    if (!user) return;

    const fetchAgents = async () => {
      try {
        const res = await fetch(
  "https://insider-threat-detection-szmm.onrender.com/api/v1/systems"
);
        const data = await res.json();

        const transformed = data
          .filter((a) => a.active !== false)
          .map((a) => ({
            id: a.agent_id,
            name: a.agent_id.replace("-", " ").toUpperCase(),
            dept: a.department || "Administrator",
          }));

        setActiveAgents(transformed);
      } catch (err) {
        console.error("Failed to fetch agents:", err);
        setActiveAgents([]);
      } finally {
        setLoadingAgents(false);
      }
    };

    fetchAgents();
    const interval = setInterval(fetchAgents, 30000);
    return () => clearInterval(interval);
  }, [user]);

  // 🔐 Not logged in → Login
  if (!user) {
    return <Login onSuccess={setUser} />;
  }

  // 🧠 Logged in, no agent selected → Agent menu
  if (!agentId) {
    if (loadingAgents) {
      return (
        <div style={{ color: "#aaa", padding: 40 }}>
          Waiting for backend telemetry…
        </div>
      );
    }

    return (
      <AgentSelect
        activeAgents={activeAgents}
        onSelectAgent={setAgentId}
      />
    );
  }

  // 📊 Agent selected → Dashboard
  return (
    <Dashboard
      agentId={agentId}
      onBack={() => setAgentId(null)}
      onLogout={() => {
        localStorage.removeItem("dikoryx_session");
        setUser(null);
        setAgentId(null);
      }}
    />
  );
}

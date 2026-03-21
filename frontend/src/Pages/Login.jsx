import { useState, useEffect } from "react";
import Dashboard from "./Pages/Dashboard";
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

    // Simulate network delay for effect
    await new Promise((r) => setTimeout(r, 400));

    if (username === "admin" && password === "1234") {
      try {
        // Save both the user AND the exact time of login
        localStorage.setItem("itd_user", "admin");
        localStorage.setItem("itd_login_time", Date.now().toString());
      } catch (err) {
        console.error("Failed to save session:", err);
      }
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
            <circle cx="12" cy="8" r="4" fill="none" stroke="currentColor" strokeWidth="1.5"/>
            <path d="M4 20c1.5-4 14.5-4 16 0" fill="none" stroke="currentColor" strokeWidth="1.5"/>
          </svg>
        </div>

        <h1 className="dkx-title">Dikoryx</h1>
        <p className="dkx-sub">Prove you're not just another glitch.</p>

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

        <div className="dkx-footer">
          Authorized personnel only
        </div>
      </div>
    </div>
  );
}

/* ================= APP CONTROLLER ================= */

export default function App() {
  const [user, setUser] = useState(null);
  
  // This state prevents the login screen from flashing before we finish checking storage
  const [isCheckingSession, setIsCheckingSession] = useState(true); 

  useEffect(() => {
    try {
      const storedUser = localStorage.getItem("itd_user");
      const loginTime = localStorage.getItem("itd_login_time");

      if (storedUser && loginTime) {
        // Calculate hours elapsed since the saved login time
        const hoursSinceLogin = (Date.now() - parseInt(loginTime)) / (1000 * 60 * 60);
        
        if (hoursSinceLogin < 24) {
          setUser(storedUser); // Session is valid! Log them in automatically.
        } else {
          // Session expired (older than 24 hours), clear the memory
          localStorage.removeItem("itd_user");
          localStorage.removeItem("itd_login_time");
        }
      }
    } catch (error) {
      console.error("Storage check failed", error);
    }
    
    // We are done checking, safe to render the app now
    setIsCheckingSession(false); 
  }, []);

  // Show a blank dark screen for a split second while calculating session status
  if (isCheckingSession) {
    return <div style={{ backgroundColor: "#050a14", height: "100vh", width: "100vw" }} />;
  }

  // If no valid session was found, show the Login screen
  if (!user) {
    return <Login onSuccess={setUser} />;
  }

  // If logged in, show the Dashboard
  return (
    <Dashboard
      onLogout={() => {
        try {
          // Completely wipe the session on manual logout
          localStorage.removeItem("itd_user");
          localStorage.removeItem("itd_login_time");
        } catch {}
        setUser(null);
      }}
    />
  );
}
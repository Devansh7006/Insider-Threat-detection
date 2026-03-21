import React from "react";
import { ShieldAlert, Activity } from "lucide-react";
import "./SystemList.css";

export default function SystemList({ systems, riskMap, selected, onSelect }) {
  
  const getEmployeeData = (sys) => {
    // Logged-in username: from heartbeat, os (events), or auth
    const username = sys?.username ?? sys?.os?.username ?? sys?.auth?.last_user ?? null;
    const isAdmin = sys?.os?.is_admin === true;
    return {
      name: username || "—",
      role: isAdmin ? "Administrator" : (username ? "User" : "Endpoint"),
      avatar: `https://i.pravatar.cc/150?u=${username || sys?.agent_id}`
    };
  };

  return (
    <div className="system-list-wrapper">
      <div className="sidebar-header">
        <Activity size={16} color="var(--neon-cyan)" />
        <span>ACTIVE_OPERATIVES</span>
      </div>

      <div className="endpoint-list">
        {systems.length === 0 && (
          <div className="no-endpoints mono">NO SIGNALS DETECTED</div>
        )}

        {systems.map((sys) => {
          const risk = riskMap[sys.agent_id] || {};
          const isSelected = selected === sys.agent_id;
          const employee = getEmployeeData(sys);
          
          // Calculate if heartbeat is active (within last 10 mins)
          const isNodeActive = sys.last_seen && ((Date.now() / 1000) - sys.last_seen) < 600;

          return (
            <div
              key={sys.agent_id}
              className={`endpoint-card ${isSelected ? "selected" : ""}`}
              onClick={() => onSelect(sys.agent_id)}
            >
              {/* Top Section: Avatar & Details */}
              <div className="card-top">
                <div className="avatar-wrapper">
                  <img src={employee.avatar} alt="Avatar" />
                  <div className={`status-dot ${isNodeActive ? 'active' : 'inactive'}`}></div>
                </div>
                
                <div className="employee-info">
                  <div className="emp-name text-glow">{employee.name}</div>
                  <div className="emp-role">{employee.role}</div>
                  <div className="agent-id mono">ID: {sys.agent_id}</div>
                </div>
              </div>

              {/* Bottom Section: Risk & Heartbeat */}
              <div className="card-bottom">
                <div className={`risk-badge ${risk.risk_level?.toLowerCase() || "low"}`}>
                  <ShieldAlert size={12} />
                  <span>{risk.risk_level || "LOW"} : {risk.risk_score || 0}</span>
                </div>
                <div className="last-seen mono">
                  {sys.last_seen ? new Date(sys.last_seen * 1000).toLocaleTimeString() : "UNKNOWN"}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
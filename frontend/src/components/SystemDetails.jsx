import React, { useEffect, useState, useCallback, useMemo } from "react";
import { 
  ShieldAlert, Activity, HardDrive, Network, Copy, 
  Globe, Cpu, RefreshCw, Terminal, Lock, AlertTriangle, 
  X, User 
} from "lucide-react";
import { AreaChart, Area, ResponsiveContainer } from 'recharts';
import { API } from "../api";
import dashboardBg from "../assets/dashboard-bg.jpg"; 
import "./SystemDetails.css";

/* ================= LOGIC ================= */
function useAgentData(agentId) {
  const [data, setData] = useState({ system: null, events: [], risk: null, compliance: null, resolvedOs: null });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const fetchData = useCallback(() => {
    if (!agentId) return;
    setLoading(true);
    Promise.all([
      API.getSystem(agentId).catch(() => ({})),
      API.getRisk(agentId).catch(() => null),
    ]).then(([sysData, riskData]) => {
      const events = Array.isArray(sysData.events) ? sysData.events : [];
      const system = sysData.system ?? null;

      // OS — Level 1: system.os (from heartbeat or backend ingest)
      let resolvedOs = system?.os ?? null;

      // OS — Level 2: scan events for most recent event with "os" (agent sends os in every event)
      if (!resolvedOs || Object.keys(resolvedOs).length === 0) {
        const eventsWithOs = events
          .filter(ev => ev.os && typeof ev.os === "object")
          .sort((a, b) => {
            const tsA = a.received_at ?? a.timestamp ?? 0;
            const tsB = b.received_at ?? b.timestamp ?? 0;
            return tsB - tsA;
          });
        if (eventsWithOs.length > 0) resolvedOs = eventsWithOs[0].os;
      }

      // COMPLIANCE — Level 1: system.compliance (stored by backend on ingest)
      let resolvedCompliance = system?.compliance ?? null;

      // COMPLIANCE — Level 2: scan events array for COMPLIANCE_STATUS
      // (compliance.py emits exactly "COMPLIANCE_STATUS" — match it exactly)
      if (!resolvedCompliance) {
        const complianceEvents = events
          .filter(ev => {
            const t = (ev.event_type || "").toUpperCase();
            return t === "COMPLIANCE_STATUS" || t === "COMPLIANCE_EVENT";
          })
          .sort((a, b) => {
            const tsA = a.received_at ?? a.timestamp ?? 0;
            const tsB = b.received_at ?? b.timestamp ?? 0;
            return tsB - tsA; // newest first
          });

        if (complianceEvents.length > 0) {
          const ev = complianceEvents[0];
          resolvedCompliance = {
            compliance_score: ev.compliance_score ?? null,
            controls: ev.controls ?? {},
            enforced: ev.enforced ?? [],
            timestamp: ev.timestamp,
          };
        }
      }

      setData({ system, events, risk: riskData || null, compliance: resolvedCompliance, resolvedOs });
      setError(false);
    }).catch(() => setError(true)).finally(() => setLoading(false));
  }, [agentId]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return { ...data, loading, error, refetch: fetchData };
}

function useAgentStats(events, windowSeconds = 600) {
  return useMemo(() => {
    const now = Date.now() / 1000;
    const cutoff = now - windowSeconds;
    const relevantEvents = events.filter(ev => {
      const ts = ev.received_at ?? ev.timestamp;
      return (ts > 1e12 ? ts / 1000 : ts) >= cutoff;
    });
    const stats = {
      file: { writes: 0, deletes: 0, renames: 0 },
      clipboard: { total: 0 },
      network: { sent: 0, recv: 0 },
      processes: { count: 0, distinct: new Set() }
    };
    for (const ev of relevantEvents) {
      const type = (ev.event_type || "").toUpperCase();
      const s = ev.summary || {};
      if (type === "FILE_ACTIVITY_SUMMARY") {
        stats.file.writes += (s.write || s.writes || 0);
        stats.file.deletes += (s.delete || s.deletes || 0);
        stats.file.renames += (s.rename || s.renames || 0);
      } else if (type === "CLIPBOARD_ACTIVITY_SUMMARY") {
        stats.clipboard.total += (s.copy_events || 0);
      } else if (type === "NETWORK_ACTIVITY_SUMMARY") {
        stats.network.sent += (s.bytes_sent || 0);
        stats.network.recv += (s.bytes_received || 0);
      } else if (type === "PROCESS_ACTIVITY_SUMMARY") {
        Object.keys(s).forEach(k => stats.processes.distinct.add(k));
        stats.processes.count += Object.values(s).reduce((a, b) => a + Number(b), 0);
      }
    }
    return stats;
  }, [events, windowSeconds]);
}

const formatBytes = (bytes) => {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + ["B", "KB", "MB", "GB", "TB"][i];
};

const generateChartData = (baseValue) => Array.from({ length: 15 }, (_, i) => ({
  time: i,
  traffic: Math.max(0, baseValue + (Math.random() * 50 - 25))
}));

/* ================= UI COMPONENTS ================= */
const CyberGauge = ({ score, level }) => {
  const radius = 65, stroke = 6;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const offset = circumference - (score / 100) * circumference;
  let color = "var(--neon-cyan)";
  if (level === "MEDIUM") color = "var(--neon-yellow)";
  if (level === "HIGH") color = "var(--neon-pink)";
  if (level === "CRITICAL") color = "var(--neon-red)";
  return (
    <div className="cyber-gauge-container">
      <div className="cyber-gauge">
        <svg height={radius * 2} width={radius * 2} className="gauge-svg">
          <circle stroke="rgba(255,255,255,0.05)" strokeWidth="1" fill="transparent" r={radius - 1} cx={radius} cy={radius} />
          <circle stroke="rgba(0, 240, 255, 0.1)" strokeWidth={stroke} fill="transparent" r={normalizedRadius} cx={radius} cy={radius} />
          <circle stroke={color} fill="transparent" strokeWidth={stroke}
            strokeDasharray={circumference + ' ' + circumference}
            style={{ strokeDashoffset: offset, filter: `drop-shadow(0 0 8px ${color})` }}
            r={normalizedRadius} cx={radius} cy={radius} strokeLinecap="square" className="gauge-progress" />
        </svg>
        <div className="gauge-text">
          <span className="score" style={{ color, textShadow: `0 0 10px ${color}` }}>{score}</span>
          <span className="label glitch" data-text={level}>{level}</span>
        </div>
      </div>
    </div>
  );
};

const StatRow = ({ label, value, icon: Icon, color = "cyan" }) => (
  <div className={`cyber-stat-row color-${color}`}>
    <div className="icon-box"><Icon size={16} /></div>
    <div className="stat-info">
      <span className="stat-label">{label}</span>
      <span className="stat-value mono">{value}</span>
    </div>
  </div>
);

const CompliancePanel = ({ compliance }) => {
  if (!compliance) {
    return (
      <div className="compliance-no-data">
        <AlertTriangle size={14} style={{ marginRight: 6, opacity: 0.6 }} />
        <span>No compliance data yet.</span>
        <p style={{ fontSize: "0.75rem", opacity: 0.5, marginTop: 6, marginBottom: 0 }}>
          Waiting for agent — data arrives within 5 min of first run.
        </p>
      </div>
    );
  }

  const score = compliance.compliance_score ?? null;
  const controls = compliance.controls || {};
  const enforced = compliance.enforced || [];
  const scoreColor = typeof score !== "number" ? "gray" : score >= 80 ? "green" : score >= 50 ? "yellow" : "red";

  return (
    <>
      <div className={`compliance-score compliance-${scoreColor}`}>
        <span className="label">Score</span>
        <span className="value">{score ?? "N/A"}{typeof score === "number" ? "%" : ""}</span>
      </div>
      {enforced.length > 0 && (
        <div className="compliance-enforced-note">Auto-enforced: {enforced.join(", ")}</div>
      )}
      <div className="compliance-grid">
        {[
          { label: "Firewall",        key: "firewall_enabled" },
          { label: "Disk Encryption", key: "disk_encryption" },
          { label: "Screen Lock",     key: "screen_lock_policy" },
          { label: "Antivirus",       key: "antivirus_running" },
          { label: "USB Restricted",  key: "usb_restricted" },
        ].map(({ label, key }) => (
          <div className="compliance-row" key={key}>
            <span className="label">{label}</span>
            <span className="value" style={{ color: controls[key] ? "var(--neon-cyan)" : "var(--neon-pink)" }}>
              {controls[key] ? "✔" : "✖"}
            </span>
          </div>
        ))}
      </div>
    </>
  );
};

/* ================= MAIN COMPONENT ================= */
export default function SystemDetails({ agentId }) {
  const { system, events, risk, compliance, resolvedOs, loading, error, refetch } = useAgentData(agentId);
  const stats = useAgentStats(events);
  const [showEmployeeModal, setShowEmployeeModal] = useState(false);
  const chartData = useMemo(() => generateChartData(stats.network.sent > 0 ? 50 : 10), [stats.network.sent]);

  if (!agentId) return <div className="cyber-fullscreen-msg"><span className="glitch" data-text="SELECT TARGET NODE">SELECT TARGET NODE</span></div>;
  if (loading && !system) return <div className="cyber-fullscreen-msg"><span className="pulse-text">ESTABLISHING UPLINK...</span></div>;
  if (error || !system) return <div className="cyber-fullscreen-msg error"><AlertTriangle size={40} /> <span className="glitch" data-text="CONNECTION LOST">CONNECTION LOST</span></div>;

  const vpn = system.vpn || {};
  const isNodeActive = system.last_seen && ((Date.now() / 1000) - system.last_seen) < 600;
  const nodeStatusText = isNodeActive ? "ACTIVE" : "INACTIVE";
  const nodeStatusClass = isNodeActive ? "safe-text text-glow" : "danger blink";

  return (
    <div className="cyber-dashboard-wrapper" style={{ backgroundImage: `url(${dashboardBg})` }}>
      <div className="crt-overlay"></div>
      <div className="cyber-container">

        <header className="cyber-header">
          <div className="header-left">
            <div className="logo-box pulse-glow"><Terminal size={28} color="var(--neon-cyan)" /></div>
            <div className="header-titles">
              <h1 className="glitch clickable-agent" data-text={agentId}
                onClick={() => setShowEmployeeModal(true)} title="View Personnel File">{agentId}</h1>
              <div className="subtitle">
                <span className={`mono ${nodeStatusClass}`}>[{nodeStatusText}]</span>
                <span className="sep">//</span>
                <span className={vpn.vpn || vpn.blacklisted ? "alert-text blink" : "safe-text"}>
                  {vpn.vpn ? `VPN ACTIVE • ${vpn.country || "Unknown"}` : vpn.blacklisted ? "IP BLACKLISTED" : `DIRECT • ${vpn.country || "Unknown"}`}
                </span>
              </div>
            </div>
          </div>
          <div className="header-right">
            <div className="live-indicator">
              <span className={`pulse-dot ${isNodeActive ? 'active' : 'inactive'}`}></span>
              <span className="mono">{isNodeActive ? "LIVE FEED" : "OFFLINE"}</span>
            </div>
            <button onClick={refetch} className="cyber-btn">
              <RefreshCw size={14} className="spin-on-hover" /> SYNC NODE
            </button>
          </div>
        </header>

        <div className="cyber-grid perspective-grid">

          <div className="cyber-card threat-panel card-3d">
            <div className="card-deco-line"></div>
            <div className="card-header"><ShieldAlert size={16} /> <span>THREAT_VECTOR_ANALYSIS</span></div>
            <div className="card-body centered">
              <CyberGauge score={risk?.risk_score || 0} level={risk?.risk_level || "LOW"} />
              <div className="threat-summary">
                <p className="mono">Behavioral Heuristics</p>
                <div className="animated-bar-container">
                  <div className="animated-bar" style={{ width: `${risk?.risk_score || 20}%` }}></div>
                </div>
              </div>
              {risk?.reasons?.length > 0 ? (
                <div className="threat-reasons">
                  <p className="threat-reasons-heading mono">Score Drivers</p>
                  <ul className="threat-reasons-list">
                    {risk.reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="threat-reasons threat-reasons-empty">
                  <p className="mono">No significant risk indicators in window</p>
                </div>
              )}
            </div>
          </div>

          <div className="cyber-card card-3d">
            <div className="card-deco-line"></div>
            <div className="card-header"><Globe size={16} /> <span>NETWORK_TELEMETRY</span></div>
            <div className="card-body split-body">
              <div className="sub-section">
                <StatRow icon={Globe} label="Public IP" value={vpn.ipv4 || "Unknown"} color="cyan" />
                <StatRow icon={ShieldAlert} label="VPN Status" value={vpn.vpn ? "Detected" : "Clean"} color={vpn.vpn ? "pink" : "cyan"} />
              </div>
              <div className="divider-line"></div>
              <div className="sub-section">
                <StatRow icon={Network} label="Uplink" value={formatBytes(stats.network.sent)} color="purple" />
                <StatRow icon={Globe} label="Downlink" value={formatBytes(stats.network.recv)} color="cyan" />
                <div style={{ width: '100%', height: '60px', marginTop: '10px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="#00f0ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <Area type="monotone" dataKey="traffic" stroke="#00f0ff" fillOpacity={1} fill="url(#colorTraffic)" animationDuration={2000} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>

          <div className="cyber-card card-3d">
            <div className="card-deco-line"></div>
            <div className="card-header"><Lock size={16} /> <span>SYSTEM_INTEGRITY</span></div>
            <div className="card-body">
              <div className="file-mod-section">
                <div className="file-mod-heading">
                  <HardDrive size={16} />
                  <span>File Modification</span>
                </div>
                <div className="file-mod-subgrid">
                  <div className="file-mod-sub">
                    <span className="sub-label">Writes</span>
                    <span className="sub-value mono">{stats.file.writes}</span>
                  </div>
                  <div className="file-mod-sub">
                    <span className="sub-label">Deletes</span>
                    <span className="sub-value mono">{stats.file.deletes}</span>
                  </div>
                  <div className="file-mod-sub">
                    <span className="sub-label">Renames</span>
                    <span className="sub-value mono">{stats.file.renames}</span>
                  </div>
                </div>
              </div>
              <StatRow icon={Copy} label="Clipboard Hooks" value={stats.clipboard.total} color="pink" />
              <StatRow icon={HardDrive} label="Hardware Risk" value={system.usb?.intel?.risk || "LOW"} color={system.usb?.intel?.risk === "HIGH" ? "pink" : "cyan"} />
              <StatRow icon={Cpu} label="Active Processes" value={stats.processes.distinct.size} color="cyan" />
            </div>
            <div className="card-header" style={{ marginTop: "1rem" }}>
              <Lock size={16} /> CIS_COMPLIANCE
              {compliance?.timestamp && (
                <span style={{ marginLeft: "auto", fontSize: "0.7rem", opacity: 0.5 }}>
                  {new Date(compliance.timestamp * 1000).toLocaleTimeString()}
                </span>
              )}
            </div>
            <div className="card-body">
              <CompliancePanel compliance={compliance} />
            </div>
          </div>

          <div className="cyber-card wide-panel card-3d">
            <div className="card-deco-line"></div>
            <div className="card-header"><Activity size={16} /> <span>ENVIRONMENTAL_VARIABLES</span></div>
            <div className="env-grid">
              <div className="env-item box-border">
                <span className="label">USB_MOUNT</span>
                <span className={`status mono ${system.usb?.intel?.risk === "HIGH" ? "danger blink" : "safe"}`}>
                  {system.usb?.mount ? `[ ${system.usb.mount} ]` : "UNMOUNTED"}
                </span>
              </div>
              <div className="env-item box-border">
                <span className="label">USB_FILES_SCANNED</span>
                <span className="value mono">{system.usb?.intel?.total_files ?? 0}</span>
              </div>
              <div className="env-item box-border">
                <span className="label">SUSPICIOUS_SIGNATURES</span>
                <span className={`value mono ${system.usb?.intel?.suspicious_files?.length ? "alert-text glow" : ""}`}>
                  {system.usb?.intel?.suspicious_files?.length ?? 0}
                </span>
              </div>
              <div className="env-item box-border">
                <span className="label">KERNEL_FAMILY</span>
                <span className="value mono">
                  {resolvedOs?.os_name || resolvedOs?.platform || resolvedOs?.os_family || "UNKNOWN"}
                </span>
              </div>
              <div className="env-item box-border">
                <span className="label">LAST_HEARTBEAT</span>
                <span className="value mono">{new Date(system.last_seen * 1000).toLocaleTimeString()}</span>
              </div>
            </div>
          </div>

        </div>
      </div>

      {showEmployeeModal && (
        <div className="cyber-modal-overlay" onClick={() => setShowEmployeeModal(false)}>
          <div className="cyber-modal-card card-3d" onClick={(e) => e.stopPropagation()}>
            <button className="close-btn" onClick={() => setShowEmployeeModal(false)}><X size={24} /></button>
            <div className="modal-header">
              <User size={20} color="var(--neon-cyan)" />
              <span>CLASSIFIED_PERSONNEL_FILE</span>
            </div>
            <div className="modal-content">
              <div className="profile-img-container">
                <img src={`https://i.pravatar.cc/150?u=${agentId}`} alt="Employee Profile" />
                <div className="img-scanline"></div>
              </div>
              <div className="employee-details">
                <div className="detail-group">
                  <span className="detail-label">OPERATIVE_ID</span>
                  <span className="detail-value text-glow">{agentId}</span>
                </div>
                <div className="detail-group">
                  <span className="detail-label">ASSIGNED_ROLE</span>
                  <span className="detail-value">System Architect</span>
                </div>
                <div className="detail-group">
                  <span className="detail-label">HEARTBEAT_STATUS</span>
                  <span className={`detail-value ${nodeStatusClass}`}>{nodeStatusText}</span>
                </div>
                <div className="detail-group">
                  <span className="detail-label">SECURITY_CLEARANCE</span>
                  <span className="detail-value danger">LEVEL 4 - RED</span>
                </div>
              </div>
            </div>
            <div className="barcode-decorative">||| | || ||| || || | | ||| || ||</div>
          </div>
        </div>
      )}
    </div>
  );
}

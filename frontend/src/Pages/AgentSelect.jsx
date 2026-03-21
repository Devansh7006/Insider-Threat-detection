import "../styles/agents.css";

/*
  activeAgents example:
  [
    {
      id: "agent-001",
      name: "Agent 001",
      dept: "HR Department"
    }
  ]
*/

export default function AgentSelect({ activeAgents, onSelectAgent }) {
  if (!activeAgents || activeAgents.length === 0) {
    return (
      <div className="dkx-agent-page">
        <div className="dkx-agent-panel">
          <h2>No active agents detected</h2>
          <p>Waiting for endpoint telemetry…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="dkx-agent-page">
      <div className="dkx-agent-panel">
        <div className="dkx-agent-header">
          <h1>Active Agents</h1>
          <p>Endpoints currently reporting telemetry</p>
          <h2>Someone’s system is always screaming.</h2>
        </div>

        <div className="dkx-agent-grid">
          {activeAgents.map((agent) => (
            <div
              key={agent.id}
              className="dkx-agent-card dkx-agent-active"
              onClick={() => onSelectAgent(agent.id)}
            >
              <div className="dkx-agent-avatar">
                {agent.id.split("-")[1]}
              </div>

              <div className="dkx-agent-meta">
                <span className="dkx-agent-name">{agent.name}</span>
                <span className="dkx-agent-dept">{agent.dept}</span>
              </div>

              <div className="dkx-agent-action">
                View Dashboard →
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

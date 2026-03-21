import React, { useMemo } from "react";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from "recharts";

export default function AgentCharts({ events = [] }) {

  /* ---------------- NETWORK DATA ---------------- */

  const networkData = useMemo(() => {
    const net = events
      .filter(e => e.event_type === "NETWORK_ACTIVITY_SUMMARY")
      .slice(-10);

    if (!net.length) {
      return [{ time: "No data", sent: 0, recv: 0 }];
    }

    return net.map((e, i) => ({
      time: new Date((e.timestamp || Date.now()) * 1000).toLocaleTimeString(),
      sent: e.summary?.bytes_sent ?? 0,
      recv: e.summary?.bytes_received ?? 0,
    }));
  }, [events]);

  /* ---------------- FILE DATA ---------------- */

  const fileEvent = [...events]
    .reverse()
    .find(e => e.event_type === "FILE_ACTIVITY_SUMMARY");

  const fileData = [
    { name: "Writes", value: fileEvent?.summary?.writes ?? 0 },
    { name: "Deletes", value: fileEvent?.summary?.deletes ?? 0 },
    { name: "Renames", value: fileEvent?.summary?.renames ?? 0 },
  ];

  const COLORS = ["#22c55e", "#ef4444", "#facc15"];

  return (
    <div className="chart-grid">

      {/* Network */}
      <div className="card">
        <h3>Network Traffic (Bytes)</h3>
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={networkData}>
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip />
            <Line dataKey="sent" stroke="#22d3ee" strokeWidth={2} />
            <Line dataKey="recv" stroke="#a78bfa" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* File */}
      <div className="card">
        <h3>File Activity</h3>
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={fileData}
              dataKey="value"
              outerRadius={90}
              innerRadius={55}
              label
            >
              {fileData.map((_, i) => (
                <Cell key={i} fill={COLORS[i]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </div>

    </div>
  );
}

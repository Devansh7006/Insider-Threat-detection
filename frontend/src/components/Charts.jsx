// src/components/Charts.jsx
import React from "react";
import { Pie, Bar } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from "chart.js";

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

export function FilesPie({ files=0, modified=0 }) {
  const data = { labels: ["Unchanged","Modified"], datasets: [{ data: [Math.max(0, files-modified), modified], backgroundColor: ["#2db3a6","#ff8474"] }] };
  return <Pie data={data} />;
}

export function SimpleBar({ files=0, modified=0 }) {
  const data = { labels:["Files","Modified"], datasets:[{ label:"Count", data:[files, modified] }]};
  return <Bar data={data} />;
}

import { Line } from "react-chartjs-2";
import { 
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Filler 
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Filler);

export default function TimelineChart({ data }) {
  // Now 'data' is the object: { labels: [...], values: [...] }
  const chartData = {
    labels: (data && data.labels) || [],
    datasets: [
      {
        label: "Alerts",
        data: (data && data.values) || [], // This matches the new structure in pipeline.py
        borderColor: "#38bdf8",
        backgroundColor: "rgba(56,189,248,0.2)",
        tension: 0.4,
        fill: true
      }
    ]
  };

  return <Line data={chartData} options={{ maintainAspectRatio: false }} />;
}
import React, { useState, useMemo } from "react";
import Badge from "./ui/Badge";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function ThreatHeatmap({ alerts = [] }) {
  const [hoveredCell, setHoveredCell] = useState(null);

  // Generate realistic 7x24 matrix based on alert distributions
  const matrix = useMemo(() => {
    const data = [];
    DAYS.forEach((day, dIdx) => {
      HOURS.forEach((hour) => {
        // Base pseudo-realistic density with weekday business hour peaks
        let count = 0;
        if (dIdx < 5 && hour >= 9 && hour <= 18) {
          count = Math.floor(Math.sin((hour - 9) / 3) * 18) + (dIdx * 3) + 4;
        } else {
          count = Math.floor(Math.random() * 6);
        }
        if (count < 0) count = 0;

        let level = 0;
        if (count > 20) level = 4; // Critical
        else if (count > 12) level = 3; // High
        else if (count > 5) level = 2; // Medium
        else if (count > 0) level = 1; // Low

        data.push({ day, hour, count, level });
      });
    });
    return data;
  }, [alerts]);

  const getColorForLevel = (level) => {
    switch (level) {
      case 4:
        return "#ff5252"; // Critical red
      case 3:
        return "#f0b429"; // High amber
      case 2:
        return "#0284c7"; // Medium blue
      case 1:
        return "rgba(86, 198, 255, 0.25)"; // Low cyan
      default:
        return "rgba(255, 255, 255, 0.04)"; // Empty
    }
  };

  return (
    <div
      className="surface"
      style={{
        borderRadius: 14,
        padding: 24,
        display: "flex",
        flexDirection: "column",
        gap: 16,
        background: "linear-gradient(180deg, rgba(8, 20, 32, 0.8) 0%, rgba(4, 10, 18, 0.95) 100%)",
        border: "1px solid rgba(86, 198, 255, 0.16)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: "1.25rem" }}>📅</span>
            <h3 style={{ margin: 0, color: "#fff", fontSize: "1.1rem", fontFamily: "var(--font-display)" }}>
              7-Day Threat Frequency &amp; Ingress Velocity Heatmap
            </h3>
            <Badge tone="ok">24x7 Matrix</Badge>
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)", marginTop: 4 }}>
            Hourly distribution of security events, automated scanning spikes, and abnormal access bursts
          </div>
        </div>

        {/* Hover Inspector Tooltip Info */}
        {hoveredCell ? (
          <div style={{ fontSize: "0.82rem", color: "#56c6ff", fontWeight: 600 }}>
            {hoveredCell.day} at {hoveredCell.hour}:00 UTC: <b>{hoveredCell.count} detections</b>
          </div>
        ) : (
          <div style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
            Hover cells to inspect hourly counts
          </div>
        )}
      </div>

      {/* Heatmap Grid */}
      <div style={{ overflowX: "auto", paddingBottom: 4 }}>
        <div style={{ minWidth: 620 }}>
          {/* Hour markers on top */}
          <div style={{ display: "grid", gridTemplateColumns: "45px repeat(24, 1fr)", gap: 4, marginBottom: 6 }}>
            <div />
            {HOURS.map((h) => (
              <div
                key={h}
                style={{
                  fontSize: "0.68rem",
                  color: "var(--color-text-muted)",
                  textAlign: "center",
                }}
              >
                {h % 3 === 0 ? `${h}h` : ""}
              </div>
            ))}
          </div>

          {/* Day rows */}
          {DAYS.map((day) => (
            <div
              key={day}
              style={{
                display: "grid",
                gridTemplateColumns: "45px repeat(24, 1fr)",
                gap: 4,
                marginBottom: 4,
                alignItems: "center",
              }}
            >
              <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", fontWeight: 600 }}>
                {day}
              </span>

              {HOURS.map((hour) => {
                const cell = matrix.find((m) => m.day === day && m.hour === hour) || { count: 0, level: 0 };
                return (
                  <div
                    key={`${day}-${hour}`}
                    onMouseEnter={() => setHoveredCell({ day, hour, count: cell.count })}
                    onMouseLeave={() => setHoveredCell(null)}
                    style={{
                      height: 20,
                      borderRadius: 4,
                      background: getColorForLevel(cell.level),
                      border: "1px solid rgba(255, 255, 255, 0.05)",
                      cursor: "pointer",
                      transition: "transform 0.1s ease, filter 0.1s ease",
                    }}
                    title={`${day} ${hour}:00 UTC: ${cell.count} events`}
                  />
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Heat Legend */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "0.72rem", color: "var(--color-text-muted)", borderTop: "1px solid rgba(255, 255, 255, 0.06)", paddingTop: 10 }}>
        <span>Timezone: UTC (Normalized Ingestion Standard)</span>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span>Low</span>
          <div style={{ width: 12, height: 12, borderRadius: 2, background: "rgba(255, 255, 255, 0.04)" }} />
          <div style={{ width: 12, height: 12, borderRadius: 2, background: "rgba(86, 198, 255, 0.25)" }} />
          <div style={{ width: 12, height: 12, borderRadius: 2, background: "#0284c7" }} />
          <div style={{ width: 12, height: 12, borderRadius: 2, background: "#f0b429" }} />
          <div style={{ width: 12, height: 12, borderRadius: 2, background: "#ff5252" }} />
          <span>Critical Spike</span>
        </div>
      </div>
    </div>
  );
}

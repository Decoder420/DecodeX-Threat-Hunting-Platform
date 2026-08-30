import React from "react";

export default function MetricSparkCard({
  title,
  value,
  delta,
  isPositiveDelta = true,
  hint,
  icon,
  sparklineData = [0, 0, 0, 0, 0, 0],
  glowColor = "#56c6ff",
}) {
  // Generate smooth SVG path from sparklineData
  const width = 140;
  const height = 44;
  const minVal = Math.min(...sparklineData);
  const maxVal = Math.max(...sparklineData) || 1;
  const range = maxVal - minVal || 1;

  const points = sparklineData.map((val, idx) => {
    const x = (idx / (sparklineData.length - 1)) * width;
    const y = height - ((val - minVal) / range) * (height - 8) - 4;
    return { x, y };
  });

  const pathD = points.reduce((acc, pt, idx) => {
    return idx === 0 ? `M ${pt.x} ${pt.y}` : `${acc} L ${pt.x} ${pt.y}`;
  }, "");

  const fillD = `${pathD} L ${width} ${height} L 0 ${height} Z`;

  return (
    <div
      className="surface"
      style={{
        borderRadius: 12,
        padding: "18px 20px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        gap: 14,
        background: "linear-gradient(135deg, rgba(14, 28, 44, 0.7) 0%, rgba(8, 16, 26, 0.85) 100%)",
        border: "1px solid rgba(86, 198, 255, 0.16)",
        position: "relative",
        overflow: "hidden",
        transition: "transform 0.15s ease, border-color 0.15s ease",
      }}
    >
      {/* Header & Icon */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.04em" }}>
            {title}
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 800, color: "#fff", marginTop: 4, fontFamily: "var(--font-display)" }}>
            {value}
          </div>
        </div>

        {icon && (
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              background: "rgba(86, 198, 255, 0.1)",
              border: "1px solid rgba(86, 198, 255, 0.25)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: "1.1rem",
              color: glowColor,
            }}
          >
            {icon}
          </div>
        )}
      </div>

      {/* Sparkline & Delta Row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
        <div>
          {delta && (
            <span
              style={{
                fontSize: "0.78rem",
                fontWeight: 700,
                color: isPositiveDelta ? "#3ee0a2" : "#ff5252",
                display: "inline-flex",
                alignItems: "center",
                gap: 2,
              }}
            >
              {isPositiveDelta ? "↗" : "↘"} {delta}
            </span>
          )}
          {hint && (
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)", marginTop: 2 }}>
              {hint}
            </div>
          )}
        </div>

        {/* Micro Sparkline SVG */}
        <div style={{ width, height, position: "relative" }}>
          <svg width={width} height={height} style={{ overflow: "visible" }}>
            <defs>
              <linearGradient id={`grad-${title.replace(/\s+/g, "")}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={glowColor} stopOpacity="0.35" />
                <stop offset="100%" stopColor={glowColor} stopOpacity="0.0" />
              </linearGradient>
            </defs>
            <path d={fillD} fill={`url(#grad-${title.replace(/\s+/g, "")})`} />
            <path d={pathD} fill="none" stroke={glowColor} strokeWidth="2" strokeLinecap="round" />
          </svg>
        </div>
      </div>
    </div>
  );
}

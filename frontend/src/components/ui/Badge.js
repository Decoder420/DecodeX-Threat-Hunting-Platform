import React from "react";

const SEVERITY_MAP = {
  critical: "badge--critical",
  high: "badge--high",
  medium: "badge--medium",
  low: "badge--low",
  open: "badge--ok",
  "in progress": "badge--info",
  quarantine: "badge--warn",
  resolved: "badge--ok",
  "false positive": "badge--low",
  live: "badge--live",
  online: "badge--ok",
  offline: "badge--warn",
};

export default function Badge({ children, tone = "info", className = "" }) {
  const key = String(tone || "").toLowerCase();
  const toneClass = SEVERITY_MAP[key] || "badge--info";
  return (
    <span className={`badge ${toneClass} ${className}`.trim()}>
      {children}
    </span>
  );
}

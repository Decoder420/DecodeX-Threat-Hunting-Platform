import React, { useEffect, useState } from "react";
import api, { API_BASE_URL } from "../api";
import Button from "../components/ui/Button";
import { getStoredToken } from "../auth";

function severityClass(sev) {
  const s = String(sev || "").toUpperCase();
  if (s === "CRITICAL") return "badge badge--critical";
  if (s === "HIGH") return "badge badge--high";
  if (s === "MEDIUM") return "badge badge--medium";
  if (s === "LOW") return "badge badge--low";
  return "badge";
}

export default function ReportsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get("/alerts", { params: { per_page: 40 } })
      .then((res) => {
        setAlerts(res.data.alerts || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const download = (id) => {
    const token = getStoredToken();
    const bust = Date.now();
    window.open(
      `${API_BASE_URL}/api/report/${id}?token=${encodeURIComponent(token)}&v=${bust}`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  return (
    <div className="page-shell">
      <h1>Incident Reports</h1>
      <p className="page-shell__copy">
        Download premium multi-page Security Incident Report PDFs (cover, executive
        summary, timeline, technical analysis, ATT&amp;CK mapping, response, RCA,
        lessons learned, and evidence register). Auth token is passed only for this
        download request.
      </p>
      <div className="surface" style={{ padding: 16 }}>
        {loading && <p className="muted">Loading alerts…</p>}
        {!loading && alerts.length === 0 && (
          <p className="muted">No alerts available to report on.</p>
        )}
        {alerts.map((a) => {
          const year = a.event_timestamp
            ? new Date(a.event_timestamp).getFullYear()
            : new Date().getFullYear();
          const irId = `IR-${year}-${String(a.id).padStart(3, "0")}`;
          return (
            <div key={a.id} className="list-row" style={{ gap: 12, alignItems: "center" }}>
              <strong style={{ minWidth: 96 }}>{irId}</strong>
              <span style={{ flex: 1 }}>{a.title || a.description}</span>
              <span className={severityClass(a.severity)}>{a.severity || "—"}</span>
              <span className="muted">{a.host || "—"}</span>
              <Button size="sm" onClick={() => download(a.id)}>
                Download PDF
              </Button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

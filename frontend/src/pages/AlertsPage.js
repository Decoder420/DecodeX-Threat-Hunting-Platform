import React, { useEffect, useState } from "react";
import api from "../api";
import Badge from "../components/ui/Badge";
import Button from "../components/ui/Button";
import { hasPermission } from "../auth";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const canWrite = hasPermission("alerts.write");

  const load = async () => {
    try {
      const res = await api.get("/alerts", { params: { per_page: 50 } });
      setAlerts(res.data.alerts || []);
    } catch (err) {
      setError("Failed to load alerts.");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const createCase = async (alertId) => {
    try {
      const res = await api.post(`/alerts/${alertId}/create_case`);
      window.alert(`Case created: ${res.data.case_number}`);
    } catch {
      window.alert("Unable to create case.");
    }
  };

  return (
    <div className="page-shell">
      <h1>Alerts</h1>
      <p className="page-shell__copy">Detection output with risk score and MITRE mapping.</p>
      {error ? <div className="login-card__error">{error}</div> : null}
      <div className="surface" style={{ padding: 16, overflowX: "auto" }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th>Risk</th>
              <th>Tactic</th>
              <th>Technique</th>
              <th>Host</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td>{a.id}</td>
                <td>{a.title || a.description}</td>
                <td><Badge tone={a.severity}>{a.severity}</Badge></td>
                <td>{a.risk_score}</td>
                <td>{a.tactic || "—"}</td>
                <td>{a.technique_id || "—"}</td>
                <td>{a.host}</td>
                <td>{a.status}</td>
                <td>
                  {canWrite ? (
                    <Button size="sm" onClick={() => createCase(a.id)}>
                      Create Case
                    </Button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

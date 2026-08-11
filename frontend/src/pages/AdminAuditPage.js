import React, { useEffect, useState } from "react";
import api from "../api";

export default function AdminAuditPage() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    api.get("/audit").then((res) => setLogs(res.data.logs || [])).catch(() => {});
  }, []);

  return (
    <div className="page-shell">
      <h1>Audit Logs</h1>
      <p className="page-shell__copy">Append-only security-relevant actions (login, RBAC, SOAR, scans).</p>
      <div className="surface" style={{ padding: 16, maxHeight: 640, overflow: "auto" }}>
        {logs.map((l) => (
          <div key={l.id} className="list-row">
            <span>{l.timestamp}</span>
            <strong>{l.username || "—"}</strong>
            <span>{l.action}</span>
            <span>{l.resource_type}:{l.resource_id}</span>
            <span className="muted">{l.details}</span>
            <span>{l.success ? "OK" : "FAIL"}</span>
          </div>
        ))}
        {!logs.length ? <div className="muted">No audit records yet.</div> : null}
      </div>
    </div>
  );
}

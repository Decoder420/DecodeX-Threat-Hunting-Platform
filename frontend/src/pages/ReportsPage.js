import React, { useEffect, useState } from "react";
import api, { API_BASE_URL } from "../api";
import Button from "../components/ui/Button";
import { getStoredToken } from "../auth";

export default function ReportsPage() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    api.get("/alerts", { params: { per_page: 30 } }).then((res) => {
      setAlerts(res.data.alerts || []);
    }).catch(() => {});
  }, []);

  const download = (id) => {
    const token = getStoredToken();
    window.open(
      `${API_BASE_URL}/api/report/${id}?token=${encodeURIComponent(token)}`,
      "_blank"
    );
  };

  return (
    <div className="page-shell">
      <h1>Reports</h1>
      <p className="page-shell__copy">
        Generate authenticated PDF incident reports (token is not embedded in bookmarks you share).
      </p>
      <div className="surface" style={{ padding: 16 }}>
        {alerts.map((a) => (
          <div key={a.id} className="list-row">
            <strong>#{a.id}</strong>
            <span>{a.title || a.description}</span>
            <span>{a.host}</span>
            <Button size="sm" onClick={() => download(a.id)}>PDF</Button>
          </div>
        ))}
      </div>
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import api, { API_BASE_URL, deleteAlert, purgeAlerts } from "../api";
import Badge from "../components/ui/Badge";
import Button from "../components/ui/Button";
import AiTriageDrawer from "../components/AiTriageDrawer";
import { getStoredToken, hasPermission } from "../auth";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);

  // AI Triage
  const [aiOpen, setAiOpen] = useState(false);
  const [aiData, setAiData] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);

  const triggerAiTriage = async (alert) => {
    setAiLoading(true);
    try {
      const res = await api.post(`/ai/alert-triage/${alert.id}`);
      setAiData(res.data);
      setAiOpen(true);
    } catch {
      window.alert("Failed to run AI triage on this alert.");
    } finally {
      setAiLoading(false);
    }
  };

  const canWrite = hasPermission("alerts.write");
  const canCase = hasPermission("cases.write");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.get("/alerts", { params: { per_page: 200 } });
      setAlerts(res.data.alerts || []);
    } catch (err) {
      setError("Failed to load alerts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const createCase = async (alertId) => {
    try {
      const res = await api.post(`/alerts/${alertId}/create_case`);
      window.alert(`Case created: ${res.data.case_number}`);
      load();
    } catch {
      window.alert("Unable to create case.");
    }
  };

  const handleDeleteAlert = async (alertId) => {
    if (!window.confirm(`Permanently delete alert #${alertId}? This will remove it from the database to save space.`)) {
      return;
    }
    try {
      await deleteAlert(alertId);
      setAlerts((prev) => prev.filter((a) => a.id !== alertId));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(null);
      }
    } catch {
      window.alert("Failed to delete alert.");
    }
  };

  const handlePurgeFalsePositives = async () => {
    if (!window.confirm("Purge all FALSE_POSITIVE alerts? This permanently removes them to keep the database lightweight and healthy.")) {
      return;
    }
    try {
      const res = await purgeAlerts({ status: "FALSE_POSITIVE" });
      window.alert(`Cleaned up ${res.data.deleted_count || 0} false positive alerts.`);
      load();
    } catch {
      window.alert("Failed to purge false positive alerts.");
    }
  };

  const updateStatus = async (alertId, newStatus) => {
    setUpdatingId(alertId);
    try {
      await api.post(`/alerts/${alertId}/status`, { status: newStatus });
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
      );
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert((prev) => ({ ...prev, status: newStatus }));
      }
    } catch (err) {
      window.alert("Failed to update status.");
    } finally {
      setUpdatingId(null);
    }
  };

  const downloadReport = (alertId) => {
    const token = getStoredToken();
    const bust = Date.now();
    const baseUrl = API_BASE_URL || window.location.origin;
    window.open(
      `${baseUrl}/api/report/${alertId}?token=${encodeURIComponent(token)}&v=${bust}`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  const exportCsv = () => {
    const headers = [
      "ID",
      "Title",
      "Severity",
      "Risk Score",
      "Status",
      "Host",
      "User",
      "Tactic",
      "Technique",
      "Timestamp",
    ];
    const rows = filteredAlerts.map((a) => [
      a.id,
      `"${(a.title || a.description || "").replace(/"/g, '""')}"`,
      a.severity,
      a.risk_score,
      a.status,
      a.host || "",
      a.user || "",
      a.tactic || "",
      a.technique_id || "",
      a.event_timestamp || a.created_at || "",
    ]);
    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `alerts_export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      const matchSearch =
        !search ||
        (a.title || "").toLowerCase().includes(search.toLowerCase()) ||
        (a.description || "").toLowerCase().includes(search.toLowerCase()) ||
        (a.host || "").toLowerCase().includes(search.toLowerCase()) ||
        (a.technique_id || "").toLowerCase().includes(search.toLowerCase()) ||
        (a.tactic || "").toLowerCase().includes(search.toLowerCase());

      const matchSev =
        severityFilter === "ALL" ||
        (a.severity || "").toUpperCase() === severityFilter;

      const matchStatus =
        statusFilter === "ALL" ||
        (a.status || "").toUpperCase() === statusFilter;

      return matchSearch && matchSev && matchStatus;
    });
  }, [alerts, search, severityFilter, statusFilter]);

  const kpis = useMemo(() => {
    const total = alerts.length;
    const open = alerts.filter(
      (a) => (a.status || "OPEN").toUpperCase() === "OPEN"
    ).length;
    const investigating = alerts.filter(
      (a) => (a.status || "").toUpperCase() === "INVESTIGATING"
    ).length;
    const critical = alerts.filter(
      (a) => (a.severity || "").toUpperCase() === "CRITICAL"
    ).length;
    const resolved = alerts.filter(
      (a) =>
        (a.status || "").toUpperCase() === "CLOSED" ||
        (a.status || "").toUpperCase() === "RESOLVED"
    ).length;
    const falsePositives = alerts.filter(
      (a) => (a.status || "").toUpperCase() === "FALSE_POSITIVE"
    ).length;
    return { total, open, investigating, critical, resolved, falsePositives };
  }, [alerts]);

  return (
    <div className="page-shell">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>Alerts Triage & Investigation</h1>
          <p className="page-shell__copy">
            Live detection stream with dynamic risk scoring, MITRE ATT&amp;CK correlation, and automated case creation.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {canWrite && kpis.falsePositives > 0 ? (
            <Button
              size="sm"
              onClick={handlePurgeFalsePositives}
              style={{ color: "var(--danger, #ff5c7a)", borderColor: "rgba(255, 92, 122, 0.4)" }}
              title="Delete all false positives from database"
            >
              🧹 Purge False Positives ({kpis.falsePositives})
            </Button>
          ) : null}
          <Button size="sm" onClick={load}>
            ↻ Refresh
          </Button>
          <Button size="sm" onClick={exportCsv} disabled={!filteredAlerts.length}>
            📥 Export CSV
          </Button>
        </div>
      </div>

      {error ? <div className="login-card__error">{error}</div> : null}

      {/* KPI STATS BAR */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div className="surface" style={{ padding: "12px 16px", borderRadius: 8 }}>
          <div className="muted" style={{ fontSize: "0.78rem", textTransform: "uppercase" }}>Total Alerts</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700 }}>{kpis.total}</div>
        </div>
        <div className="surface" style={{ padding: "12px 16px", borderRadius: 8, borderLeft: "3px solid var(--danger, #ff5c7a)" }}>
          <div className="muted" style={{ fontSize: "0.78rem", textTransform: "uppercase" }}>Critical Severity</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700, color: "var(--danger, #ff5c7a)" }}>{kpis.critical}</div>
        </div>
        <div className="surface" style={{ padding: "12px 16px", borderRadius: 8, borderLeft: "3px solid var(--warn, #f0b429)" }}>
          <div className="muted" style={{ fontSize: "0.78rem", textTransform: "uppercase" }}>Open Pending</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700, color: "var(--warn, #f0b429)" }}>{kpis.open}</div>
        </div>
        <div className="surface" style={{ padding: "12px 16px", borderRadius: 8, borderLeft: "3px solid var(--info, #5ec8ff)" }}>
          <div className="muted" style={{ fontSize: "0.78rem", textTransform: "uppercase" }}>Investigating</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700, color: "var(--info, #5ec8ff)" }}>{kpis.investigating}</div>
        </div>
        <div className="surface" style={{ padding: "12px 16px", borderRadius: 8, borderLeft: "3px solid var(--ok, #3ee0a2)" }}>
          <div className="muted" style={{ fontSize: "0.78rem", textTransform: "uppercase" }}>Closed / Resolved</div>
          <div style={{ fontSize: "1.6rem", fontWeight: 700, color: "var(--ok, #3ee0a2)" }}>{kpis.resolved}</div>
        </div>
      </div>

      {/* FILTER & SEARCH BAR */}
      <div className="surface" style={{ padding: 14, marginBottom: 16, display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        <input
          className="field__input"
          style={{ flex: "1 1 240px", minWidth: 200 }}
          placeholder="Search by title, host, tactic, technique ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>Severity:</span>
          <select
            className="field__input"
            style={{ width: "auto", padding: "6px 10px" }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>Status:</span>
          <select
            className="field__input"
            style={{ width: "auto", padding: "6px 10px" }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CLOSED">Closed</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>
      </div>

      {/* ALERTS TABLE */}
      <div className="surface" style={{ padding: 16, overflowX: "auto" }}>
        {loading ? (
          <p className="muted">Loading detections…</p>
        ) : !filteredAlerts.length ? (
          <p className="muted">No matching alerts found.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Title / Detection</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>MITRE Tactic</th>
                <th>Technique</th>
                <th>Host</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.map((a) => (
                <tr
                  key={a.id}
                  style={{
                    cursor: "pointer",
                    background: selectedAlert?.id === a.id ? "rgba(62, 224, 162, 0.06)" : undefined,
                  }}
                  onClick={() => setSelectedAlert(a)}
                >
                  <td><strong>#{a.id}</strong></td>
                  <td style={{ maxWidth: 280 }}>
                    <div style={{ fontWeight: 600 }}>{a.title || a.description}</div>
                    {a.event_timestamp ? (
                      <div className="muted" style={{ fontSize: "0.75rem" }}>
                        {new Date(a.event_timestamp).toLocaleString()}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    <Badge tone={a.severity}>{a.severity}</Badge>
                  </td>
                  <td>
                    <span
                      style={{
                        fontWeight: 700,
                        color:
                          a.risk_score >= 80
                            ? "var(--danger, #ff5c7a)"
                            : a.risk_score >= 50
                            ? "var(--warn, #f0b429)"
                            : "var(--text, #fff)",
                      }}
                    >
                      {a.risk_score}
                    </span>
                  </td>
                  <td>{a.tactic || "—"}</td>
                  <td>
                    {a.technique_id ? (
                      <a
                        href={`https://attack.mitre.org/techniques/${a.technique_id.replace(/\./g, "/")}/`}
                        target="_blank"
                        rel="noreferrer"
                        style={{ color: "var(--info, #5ec8ff)", textDecoration: "none" }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {a.technique_id}
                      </a>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td><code>{a.host || "—"}</code></td>
                  <td>
                    <Badge tone={a.status === "CLOSED" ? "ok" : a.status === "INVESTIGATING" ? "info" : "warn"}>
                      {a.status || "OPEN"}
                    </Badge>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <Button size="sm" onClick={() => setSelectedAlert(a)}>
                        Inspect
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => triggerAiTriage(a)}
                        style={{ borderColor: "rgba(86, 198, 255, 0.4)", color: "#56c6ff" }}
                      >
                        🤖 AI
                      </Button>
                      {canCase ? (
                        <Button size="sm" onClick={() => createCase(a.id)}>
                          Case
                        </Button>
                      ) : null}
                      <Button size="sm" onClick={() => downloadReport(a.id)}>
                        PDF
                      </Button>
                      {canWrite ? (
                        <Button
                          size="sm"
                          onClick={() => handleDeleteAlert(a.id)}
                          style={{ color: "var(--danger, #ff5c7a)", borderColor: "rgba(255, 92, 122, 0.3)" }}
                          title="Delete alert permanently"
                        >
                          🗑️
                        </Button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ALERT INSPECTION MODAL / DRAWER */}
      {selectedAlert ? (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.7)",
            display: "flex",
            justifyContent: "flex-end",
            zIndex: 9999,
          }}
          onClick={() => setSelectedAlert(null)}
        >
          <div
            className="surface"
            style={{
              width: "100%",
              maxWidth: 620,
              height: "100%",
              overflowY: "auto",
              padding: 24,
              boxShadow: "var(--shadow, 0 18px 50px rgba(0,0,0,0.7))",
              borderLeft: "1px solid var(--line-strong, rgba(148, 197, 184, 0.28))",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
              <div>
                <span className="muted" style={{ fontSize: "0.85rem" }}>ALERT DETAILS #{selectedAlert.id}</span>
                <h2 style={{ margin: "4px 0 8px" }}>{selectedAlert.title || selectedAlert.description}</h2>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <Badge tone={selectedAlert.severity}>{selectedAlert.severity}</Badge>
                  <span className="muted">Risk Score:</span>
                  <strong>{selectedAlert.risk_score}/100</strong>
                </div>
              </div>
              <Button size="sm" onClick={() => setSelectedAlert(null)}>
                ✕ Close
              </Button>
            </div>

            {/* QUICK STATUS TRIAGE */}
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(255, 255, 255, 0.03)",
                border: "1px solid var(--line, rgba(255,255,255,0.08))",
                borderRadius: 8,
                marginBottom: 18,
              }}
            >
              <div className="muted" style={{ fontSize: "0.8rem", marginBottom: 8, textTransform: "uppercase" }}>
                Triage Status Workflow
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {canWrite ? (
                  ["OPEN", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"].map((st) => (
                    <Button
                      key={st}
                      size="sm"
                      variant={selectedAlert.status === st ? "primary" : undefined}
                      disabled={updatingId === selectedAlert.id}
                      onClick={() => updateStatus(selectedAlert.id, st)}
                    >
                      {st === "FALSE_POSITIVE" ? "False Positive" : st}
                    </Button>
                  ))
                ) : (
                  <span className="muted" style={{ fontSize: "0.82rem" }}>
                    Read-only permissions (alerts.write required to triage status)
                  </span>
                )}
              </div>

            </div>

            {/* EVENT METADATA GRID */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 18 }}>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Host Asset:</span>
                <div><code>{selectedAlert.host || "—"}</code></div>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Username / Identity:</span>
                <div><code>{selectedAlert.user || "—"}</code></div>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Detection Rule:</span>
                <div>{selectedAlert.rule_name || "Built-in Hunting Rule"}</div>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Timestamp:</span>
                <div>{selectedAlert.event_timestamp ? new Date(selectedAlert.event_timestamp).toLocaleString() : "—"}</div>
              </div>
            </div>

            {/* MITRE ATT&CK CARD */}
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(94, 200, 255, 0.06)",
                border: "1px solid rgba(94, 200, 255, 0.2)",
                borderRadius: 8,
                marginBottom: 18,
              }}
            >
              <div style={{ fontWeight: 600, color: "var(--info, #5ec8ff)", marginBottom: 4 }}>
                🎯 MITRE ATT&amp;CK Mapping
              </div>
              <div><strong>Tactic:</strong> {selectedAlert.tactic || "Execution"}</div>
              <div>
                <strong>Technique ID:</strong>{" "}
                {selectedAlert.technique_id ? (
                  <a
                    href={`https://attack.mitre.org/techniques/${selectedAlert.technique_id.replace(/\./g, "/")}/`}
                    target="_blank"
                    rel="noreferrer"
                    style={{ color: "var(--info, #5ec8ff)" }}
                  >
                    {selectedAlert.technique_id} ↗
                  </a>
                ) : (
                  "T1059 (Command and Scripting Interpreter)"
                )}
              </div>
            </div>

            {/* COMMANDLINE EVIDENCE */}
            {selectedAlert.commandline ? (
              <div style={{ marginBottom: 18 }}>
                <div className="muted" style={{ fontSize: "0.8rem", marginBottom: 4 }}>Command-Line Execution:</div>
                <pre
                  style={{
                    background: "#03070d",
                    padding: 10,
                    borderRadius: 6,
                    border: "1px solid var(--line, #222)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    fontSize: "0.8rem",
                    color: "var(--accent, #3ee0a2)",
                  }}
                >
                  {selectedAlert.commandline}
                </pre>
              </div>
            ) : null}

            {/* ACTION SHORTCUTS */}
            <div style={{ display: "flex", gap: 10, marginTop: 24, borderTop: "1px solid var(--line, rgba(255,255,255,0.1))", paddingTop: 16, flexWrap: "wrap" }}>
              <Button
                variant="primary"
                disabled={aiLoading}
                onClick={() => triggerAiTriage(selectedAlert)}
                style={{ background: "linear-gradient(135deg, #0288d1 0%, #00acc1 100%)" }}
              >
                🤖 Run AI Threat Triage &amp; WAF Rules
              </Button>
              {canCase ? (
                <Button onClick={() => createCase(selectedAlert.id)}>
                  🛡️ Escalate to Case
                </Button>
              ) : null}
              <Button onClick={() => downloadReport(selectedAlert.id)}>
                📄 Download Incident Report (PDF)
              </Button>
              {canWrite ? (
                <Button
                  onClick={() => handleDeleteAlert(selectedAlert.id)}
                  style={{ color: "var(--danger, #ff5c7a)", borderColor: "var(--danger, #ff5c7a)" }}
                >
                  🗑️ Delete Alert
                </Button>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      {/* AI TRIAGE DRAWER */}
      <AiTriageDrawer
        isOpen={aiOpen}
        onClose={() => setAiOpen(false)}
        data={aiData}
        type="alert"
      />
    </div>
  );
}

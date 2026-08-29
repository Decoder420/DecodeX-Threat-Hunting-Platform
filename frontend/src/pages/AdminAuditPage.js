import React, { useEffect, useState, useMemo } from "react";
import api from "../api";
import Badge from "../components/ui/Badge";
import Button from "../components/ui/Button";

export default function AdminAuditPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const load = async () => {
    setLoading(true);
    try {
      const res = await api.get("/audit");
      setLogs(res.data.logs || []);
    } catch {
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filteredLogs = useMemo(() => {
    return logs.filter((l) => {
      const matchSearch =
        !search ||
        (l.action || "").toLowerCase().includes(search.toLowerCase()) ||
        (l.username || "").toLowerCase().includes(search.toLowerCase()) ||
        (l.details || "").toLowerCase().includes(search.toLowerCase()) ||
        String(l.resource_id || "").includes(search);

      const matchAction =
        actionFilter === "ALL" ||
        (l.action || "").toLowerCase().startsWith(actionFilter.toLowerCase());

      const matchStatus =
        statusFilter === "ALL" ||
        (statusFilter === "SUCCESS" ? l.success : !l.success);

      return matchSearch && matchAction && matchStatus;
    });
  }, [logs, search, actionFilter, statusFilter]);

  const metrics = useMemo(() => {
    const total = logs.length;
    const successes = logs.filter((l) => l.success).length;
    const failures = logs.filter((l) => !l.success).length;
    const users = new Set(logs.map((l) => l.username).filter(Boolean)).size;
    return { total, successes, failures, users };
  }, [logs]);

  const exportCsv = () => {
    const headers = ["ID", "Timestamp", "User", "Action", "Resource Type", "Resource ID", "Success", "Details"];
    const rows = filteredLogs.map((l) => [
      l.id,
      l.timestamp,
      `"${(l.username || "").replace(/"/g, '""')}"`,
      `"${(l.action || "").replace(/"/g, '""')}"`,
      l.resource_type,
      l.resource_id,
      l.success ? "SUCCESS" : "FAILURE",
      `"${(l.details || "").replace(/"/g, '""')}"`,
    ]);
    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const link = document.createElement("a");
    link.href = encodeURI(csvContent);
    link.download = `decodex_audit_log_${Date.now()}.csv`;
    link.click();
  };

  return (
    <div className="page-shell">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>DecodeX Audit &amp; Compliance Trail</h1>
          <p className="page-shell__copy">
            Immutable forensic trail recording administrative actions, authentication attempts, RBAC policy changes, and SOAR response dispatches.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Button size="sm" onClick={load}>
            ↻ Refresh
          </Button>
          <Button size="sm" onClick={exportCsv} disabled={!filteredLogs.length}>
            📥 Export CSV
          </Button>
        </div>
      </div>

      {/* METRIC KPI TILES */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div className="surface" style={{ padding: "10px 14px", borderRadius: 8 }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Audit Events</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700 }}>{metrics.total}</div>
        </div>
        <div className="surface" style={{ padding: "10px 14px", borderRadius: 8, borderLeft: "3px solid var(--ok, #3ee0a2)" }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Authorized (OK)</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--ok, #3ee0a2)" }}>{metrics.successes}</div>
        </div>
        <div className="surface" style={{ padding: "10px 14px", borderRadius: 8, borderLeft: "3px solid var(--danger, #ff5c7a)" }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Security Failures</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--danger, #ff5c7a)" }}>{metrics.failures}</div>
        </div>
        <div className="surface" style={{ padding: "10px 14px", borderRadius: 8 }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Active Operators</div>
          <div style={{ fontSize: "1.5rem", fontWeight: 700 }}>{metrics.users}</div>
        </div>
      </div>

      {/* FILTER & SEARCH */}
      <div className="surface" style={{ padding: "12px 16px", marginBottom: 16, display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
        <input
          className="field__input"
          style={{ flex: "1 1 240px", minWidth: 200 }}
          placeholder="Filter by action, user, or details..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>Category:</span>
          <select
            className="field__input"
            style={{ width: "auto", padding: "6px 10px" }}
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
          >
            <option value="ALL">All Actions</option>
            <option value="auth">Auth (Login/Logout)</option>
            <option value="user">User &amp; RBAC</option>
            <option value="soar">SOAR Execution</option>
            <option value="case">Case Management</option>
            <option value="webscan">Web Security</option>
          </select>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>Result:</span>
          <select
            className="field__input"
            style={{ width: "auto", padding: "6px 10px" }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Outcomes</option>
            <option value="SUCCESS">Success (OK)</option>
            <option value="FAIL">Failed Only</option>
          </select>
        </div>
      </div>

      {/* AUDIT LOG TABLE */}
      <div className="surface" style={{ padding: 16, overflowX: "auto" }}>
        {loading ? (
          <p className="muted">Loading compliance logs…</p>
        ) : !filteredLogs.length ? (
          <p className="muted">No matching audit events found.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Operator</th>
                <th>Action</th>
                <th>Target Resource</th>
                <th>Details</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((l) => (
                <tr key={l.id}>
                  <td style={{ whiteSpace: "nowrap", fontSize: "0.8rem" }} className="muted">
                    {l.timestamp}
                  </td>
                  <td><strong>{l.username || "System"}</strong></td>
                  <td>
                    <code>{l.action}</code>
                  </td>
                  <td>
                    <span className="muted" style={{ fontSize: "0.82rem" }}>
                      {l.resource_type}:{l.resource_id}
                    </span>
                  </td>
                  <td style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <span style={{ fontSize: "0.85rem" }}>{l.details || "—"}</span>
                  </td>
                  <td>
                    <Badge tone={l.success ? "ok" : "danger"}>
                      {l.success ? "SUCCESS" : "FAILED"}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

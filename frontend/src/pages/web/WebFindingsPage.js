import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";
import { hasPermission } from "../../auth";

function severityTone(sev) {
  if (sev === "CRITICAL" || sev === "HIGH") return "danger";
  if (sev === "MEDIUM") return "warn";
  if (sev === "LOW") return "info";
  return "ok";
}

export default function WebFindingsPage() {
  const canRun = hasPermission("webscan.run");
  const canCase = hasPermission("cases.write");
  const [params] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);

  const scanFilter = params.get("scan") || "";

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await webApi.getFindings({
        q: q || undefined,
        severity: severity || undefined,
        status: status || undefined,
        scan_id: scanFilter || undefined,
        limit: 200,
      });
      setFindings(res.data.findings || []);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load findings.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, severity, status, scanFilter]);

  const openFinding = async (id) => {
    try {
      const res = await webApi.getFinding(id);
      setSelected(res.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load finding.");
    }
  };

  const updateStatus = async (next) => {
    if (!selected) return;
    await webApi.updateFinding(selected.id, { status: next });
    await openFinding(selected.id);
    await load();
  };

  const createCase = async () => {
    if (!selected) return;
    const res = await webApi.createCaseFromFinding(selected.id);
    await openFinding(selected.id);
    window.alert(`Case ${res.data.case_number || res.data.case_id} linked.`);
  };

  const sorted = useMemo(
    () => [...findings].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)),
    [findings]
  );

  const kpis = useMemo(() => {
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    const high = findings.filter((f) => f.severity === "HIGH").length;
    const medium = findings.filter((f) => f.severity === "MEDIUM").length;
    const low = findings.filter((f) => f.severity === "LOW").length;
    const info = findings.filter((f) => f.severity === "INFO").length;
    return { critical, high, medium, low, info };
  }, [findings]);

  const exportCsv = () => {
    const headers = [
      "ID",
      "Severity",
      "Risk Score",
      "Title",
      "Category",
      "Source Engine",
      "Status",
      "Affected URL",
      "CWE",
      "OWASP",
    ];
    const rows = sorted.map((f) => [
      f.id,
      f.severity,
      f.risk_score,
      `"${(f.title || "").replace(/"/g, '""')}"`,
      f.category,
      f.source_engine,
      f.status,
      `"${(f.affected_url || f.url || "").replace(/"/g, '""')}"`,
      f.cwe || "",
      f.owasp || "",
    ]);
    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const link = document.createElement("a");
    link.href = encodeURI(csvContent);
    link.download = `web_vulnerabilities_${Date.now()}.csv`;
    link.click();
  };

  return (
    <div className="websec__stack">
      {error ? <div className="surface websec__panel error-text">{error}</div> : null}

      <div className="surface websec__panel">
        <div className="websec__row">
          <div>
            <h2 style={{ margin: 0 }}>Vulnerability Findings Triage</h2>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Normalized security flaws discovered by OWASP ZAP, ProjectDiscovery Nuclei, and Built-in scanners.
            </p>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Button size="sm" onClick={load}>
              ↻ Refresh
            </Button>
            <Button size="sm" onClick={exportCsv} disabled={!sorted.length}>
              📥 Export CSV
            </Button>
          </div>
        </div>

        {/* SEVERITY KPI PILLS */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
            gap: 10,
            marginTop: 14,
            marginBottom: 16,
          }}
        >
          <div style={{ padding: "8px 12px", background: "rgba(255, 92, 122, 0.08)", border: "1px solid rgba(255, 92, 122, 0.25)", borderRadius: 6 }}>
            <div className="muted" style={{ fontSize: "0.72rem", textTransform: "uppercase" }}>Critical</div>
            <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--danger, #ff5c7a)" }}>{kpis.critical}</div>
          </div>
          <div style={{ padding: "8px 12px", background: "rgba(251, 146, 60, 0.08)", border: "1px solid rgba(251, 146, 60, 0.25)", borderRadius: 6 }}>
            <div className="muted" style={{ fontSize: "0.72rem", textTransform: "uppercase" }}>High</div>
            <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "#fb923c" }}>{kpis.high}</div>
          </div>
          <div style={{ padding: "8px 12px", background: "rgba(240, 180, 41, 0.08)", border: "1px solid rgba(240, 180, 41, 0.25)", borderRadius: 6 }}>
            <div className="muted" style={{ fontSize: "0.72rem", textTransform: "uppercase" }}>Medium</div>
            <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--warn, #f0b429)" }}>{kpis.medium}</div>
          </div>
          <div style={{ padding: "8px 12px", background: "rgba(94, 200, 255, 0.08)", border: "1px solid rgba(94, 200, 255, 0.25)", borderRadius: 6 }}>
            <div className="muted" style={{ fontSize: "0.72rem", textTransform: "uppercase" }}>Low</div>
            <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--info, #5ec8ff)" }}>{kpis.low}</div>
          </div>
          <div style={{ padding: "8px 12px", background: "rgba(255, 255, 255, 0.02)", border: "1px solid var(--line, #333)", borderRadius: 6 }}>
            <div className="muted" style={{ fontSize: "0.72rem", textTransform: "uppercase" }}>Info</div>
            <div style={{ fontSize: "1.3rem", fontWeight: 700 }}>{kpis.info}</div>
          </div>
        </div>

        {/* SEARCH & FILTERS */}
        <div className="websec__form-grid" style={{ marginBottom: 14 }}>
          <input
            className="field__input"
            placeholder="Search title, URL, evidence, CWE, template…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <select
            className="field__input"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">All severities</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            className="field__input"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">All statuses</option>
            {["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"].map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </select>
          <Button onClick={load}>Refresh</Button>
        </div>

        {loading ? <div className="muted">Loading findings catalog…</div> : null}
        {!loading && !sorted.length ? (
          <div className="muted">No findings match current filter criteria.</div>
        ) : null}

        <div className="websec__table-wrap">
          <table className="websec__table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Risk</th>
                <th>Vulnerability Title</th>
                <th>Category</th>
                <th>Engine</th>
                <th>Status</th>
                <th>Affected Endpoint</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f) => (
                <tr
                  key={f.id}
                  className="websec__click-row"
                  style={{
                    background: selected?.id === f.id ? "rgba(62, 224, 162, 0.08)" : undefined,
                  }}
                  onClick={() => openFinding(f.id)}
                >
                  <td>
                    <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                  </td>
                  <td>
                    <strong style={{ color: f.risk_score >= 70 ? "var(--danger, #ff5c7a)" : undefined }}>
                      {f.risk_score}
                    </strong>
                  </td>
                  <td>
                    <strong>{f.title}</strong>
                  </td>
                  <td>{f.category}</td>
                  <td>
                    <Badge tone="ok">{f.source_engine}</Badge>
                  </td>
                  <td>{f.status}</td>
                  <td className="websec__mono">{f.affected_url || f.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* FINDING INSPECTOR DRAWER */}
      {selected ? (
        <div className="surface websec__panel websec__drawer">
          <div className="websec__row">
            <div>
              <span className="muted" style={{ fontSize: "0.8rem" }}>VULNERABILITY FINDING #{selected.id}</span>
              <h2 style={{ margin: "4px 0" }}>{selected.title}</h2>
            </div>
            <Button size="sm" onClick={() => setSelected(null)}>
              ✕ Close
            </Button>
          </div>

          <div className="websec__kpi-grid" style={{ margin: "14px 0" }}>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Severity</div>
              <Badge tone={severityTone(selected.severity)}>{selected.severity}</Badge>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Risk Score</div>
              <div>{selected.risk_score}/100</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Confidence</div>
              <div>{selected.confidence ?? "100%"}</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Detection Engine</div>
              <div>{selected.source_engine}</div>
            </div>
          </div>

          <section style={{ marginBottom: 14 }}>
            <h3>Overview &amp; Impact</h3>
            <p style={{ margin: "4px 0", lineHeight: 1.5 }}>{selected.description || "No overview recorded."}</p>
          </section>

          <section style={{ marginBottom: 14 }}>
            <h3>Affected Endpoint URL</h3>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
              <code className="websec__mono" style={{ flex: 1, padding: 8, background: "#03070d", borderRadius: 4 }}>
                {selected.affected_url || selected.url}
              </code>
              <Button
                size="sm"
                onClick={() => {
                  navigator.clipboard?.writeText(selected.affected_url || selected.url || "");
                  window.alert("URL copied to clipboard!");
                }}
              >
                📋 Copy
              </Button>
            </div>
          </section>

          {selected.evidence ? (
            <section style={{ marginBottom: 14 }}>
              <h3>Evidence / Proof of Concept</h3>
              <pre className="websec__pre" style={{ background: "#03070d", color: "var(--accent, #3ee0a2)", maxHeight: 180, overflowY: "auto" }}>
                {selected.evidence}
              </pre>
            </section>
          ) : null}

          <section style={{ marginBottom: 14 }}>
            <h3>Remediation Guidance</h3>
            <p style={{ margin: "4px 0", lineHeight: 1.5 }}>
              {selected.remediation || selected.recommendation || "Review server configuration and apply latest security patches."}
            </p>
          </section>

          <section style={{ marginBottom: 16 }}>
            <h3>Security Classification</h3>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 6 }}>
              {selected.cwe ? (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${selected.cwe.replace(/[^0-9]/g, "")}.html`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ textDecoration: "none" }}
                >
                  <Badge tone="info">CWE: {selected.cwe} ↗</Badge>
                </a>
              ) : null}
              {selected.owasp ? <Badge tone="warn">OWASP: {selected.owasp}</Badge> : null}
              {selected.cve ? <Badge tone="danger">CVE: {selected.cve}</Badge> : null}
              {selected.template_id ? <Badge>Template: {selected.template_id}</Badge> : null}
            </div>
          </section>

          {/* STATUS ACTIONS & ESCALATION */}
          {canRun ? (
            <div
              className="websec__actions"
              style={{
                borderTop: "1px solid var(--line, rgba(255,255,255,0.1))",
                paddingTop: 14,
                marginTop: 14,
              }}
            >
              <Button size="sm" onClick={() => updateStatus("OPEN")}>
                Mark Open
              </Button>
              <Button size="sm" onClick={() => updateStatus("CONFIRMED")}>
                Confirmed
              </Button>
              <Button size="sm" onClick={() => updateStatus("FALSE_POSITIVE")}>
                False Positive
              </Button>
              <Button size="sm" onClick={() => updateStatus("RESOLVED")}>
                Resolved
              </Button>
              {canCase ? (
                <Button size="sm" variant="primary" onClick={createCase}>
                  🛡️ Escalate to SOC Case
                </Button>
              ) : null}
            </div>
          ) : null}

          {selected.case_id ? (
            <p className="muted" style={{ marginTop: 10 }}>
              Linked SOC Case ID: <strong>CASE-{selected.case_id}</strong>
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

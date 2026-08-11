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

  return (
    <div className="websec__stack">
      {error ? <div className="surface websec__panel error-text">{error}</div> : null}

      <div className="surface websec__panel">
        <h2>Findings</h2>
        <div className="websec__form-grid">
          <input
            className="field__input"
            placeholder="Search title, URL, evidence, template…"
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
                {s}
              </option>
            ))}
          </select>
          <Button onClick={load}>Refresh</Button>
        </div>

        {loading ? <div className="muted">Loading…</div> : null}
        {!loading && !sorted.length ? (
          <div className="muted">No findings match filters.</div>
        ) : null}

        <div className="websec__table-wrap">
          <table className="websec__table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Risk</th>
                <th>Title</th>
                <th>Category</th>
                <th>Engine</th>
                <th>Status</th>
                <th>URL</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((f) => (
                <tr
                  key={f.id}
                  className="websec__click-row"
                  onClick={() => openFinding(f.id)}
                >
                  <td>
                    <Badge tone={severityTone(f.severity)}>{f.severity}</Badge>
                  </td>
                  <td>{f.risk_score}</td>
                  <td>
                    <strong>{f.title}</strong>
                  </td>
                  <td>{f.category}</td>
                  <td>{f.source_engine}</td>
                  <td>{f.status}</td>
                  <td className="websec__mono">{f.affected_url || f.url}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected ? (
        <div className="surface websec__panel websec__drawer">
          <div className="websec__row">
            <h2>{selected.title}</h2>
            <Button size="sm" onClick={() => setSelected(null)}>
              Close
            </Button>
          </div>
          <div className="websec__kpi-grid">
            <div className="websec__kpi">
              <div className="websec__kpi-label">Severity</div>
              <Badge tone={severityTone(selected.severity)}>{selected.severity}</Badge>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Risk</div>
              <div>{selected.risk_score}</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Confidence</div>
              <div>{selected.confidence}</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Engine</div>
              <div>{selected.source_engine}</div>
            </div>
          </div>

          <section>
            <h3>Overview</h3>
            <p>{selected.description || "—"}</p>
          </section>
          <section>
            <h3>Affected URL</h3>
            <code className="websec__mono">{selected.affected_url || selected.url}</code>
            <Button
              size="sm"
              onClick={() =>
                navigator.clipboard?.writeText(selected.affected_url || selected.url || "")
              }
            >
              Copy URL
            </Button>
          </section>
          <section>
            <h3>Evidence</h3>
            <pre className="websec__pre">{selected.evidence || "—"}</pre>
          </section>
          <section>
            <h3>Remediation</h3>
            <p>{selected.remediation || selected.recommendation || "—"}</p>
          </section>
          <section>
            <h3>Classification</h3>
            <ul>
              <li>CWE: {selected.cwe || "—"}</li>
              <li>OWASP: {selected.owasp || "—"}</li>
              <li>CVE: {selected.cve || "—"}</li>
              <li>CVSS: {selected.cvss || "—"}</li>
              <li>Template: {selected.template_id || "—"}</li>
            </ul>
          </section>
          {selected.risk_factors ? (
            <section>
              <h3>Risk factors</h3>
              <pre className="websec__pre">
                {JSON.stringify(selected.risk_factors, null, 2)}
              </pre>
            </section>
          ) : null}

          {canRun ? (
            <div className="websec__actions">
              <Button size="sm" onClick={() => updateStatus("OPEN")}>
                Mark Open
              </Button>
              <Button size="sm" onClick={() => updateStatus("CONFIRMED")}>
                Confirmed
              </Button>
              <Button size="sm" onClick={() => updateStatus("FALSE_POSITIVE")}>
                False positive
              </Button>
              <Button size="sm" onClick={() => updateStatus("RESOLVED")}>
                Resolved
              </Button>
              {canCase ? (
                <Button size="sm" variant="primary" onClick={createCase}>
                  Create case
                </Button>
              ) : null}
            </div>
          ) : null}
          {selected.case_id ? (
            <p className="muted">Linked case ID: {selected.case_id}</p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

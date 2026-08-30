import React, { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import api from "../../api";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";
import AiTriageDrawer from "../../components/AiTriageDrawer";
import AttackBlastRadiusGraph from "../../components/AttackBlastRadiusGraph";
import { hasPermission } from "../../auth";
import { renderScanStatusBadge } from "./WebScansPage";

export default function WebTargetDetailPage() {
  const { targetId } = useParams();
  const navigate = useNavigate();
  const canRun = hasPermission("webscan.run");

  const [cockpit, setCockpit] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("findings");
  const [findingFilter, setFindingFilter] = useState("ALL");
  const [scanBusy, setScanBusy] = useState(false);

  // AI Triage State
  const [aiDrawerOpen, setAiDrawerOpen] = useState(false);
  const [aiData, setAiData] = useState(null);
  const [aiType, setAiType] = useState("finding");
  const [aiLoading, setAiLoading] = useState(false);

  const loadCockpit = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api.get(`/webscan/targets/${targetId}/cockpit`);
      setCockpit(res.data);
    } catch (err) {
      setError(err.response?.data?.error || "Failed to load target investigation details.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCockpit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId]);

  const handleRunScan = async (profile = "QUICK") => {
    if (!cockpit?.target) return;
    setScanBusy(true);
    try {
      await webApi.runScan({
        target_id: cockpit.target.id,
        scan_profile: profile,
      });
      window.alert(`Scan started for ${cockpit.target.name}! Check the scans tab.`);
      await loadCockpit();
      setActiveTab("scans");
    } catch (err) {
      window.alert(err.response?.data?.error?.message || "Failed to trigger scan.");
    } finally {
      setScanBusy(false);
    }
  };

  const handleAuthorize = async () => {
    if (!cockpit?.target) return;
    const ok = window.confirm(
      `Confirm explicit authorization to scan ${cockpit.target.name} (${cockpit.target.url})?\n\n` +
        "Only confirm if you have explicit permission to assess this asset."
    );
    if (!ok) return;
    try {
      await webApi.authorizeTarget(cockpit.target.id);
      window.alert(`✓ Target "${cockpit.target.name}" is now AUTHORIZED and ready for scanning!`);
      await loadCockpit();
    } catch (err) {
      const msg = err.response?.data?.error?.message || err.message || "Failed to authorize target.";
      window.alert(`Authorization failed: ${msg}`);
    }
  };

  const triggerFindingAi = async (finding) => {
    setAiLoading(true);
    try {
      const res = await api.post(`/ai/finding-triage/${finding.id}`);
      setAiData(res.data);
      setAiType("finding");
      setAiDrawerOpen(true);
    } catch {
      window.alert("Failed to run AI triage on this finding.");
    } finally {
      setAiLoading(false);
    }
  };

  const triggerAlertAi = async (alert) => {
    setAiLoading(true);
    try {
      const res = await api.post(`/ai/alert-triage/${alert.id}`);
      setAiData(res.data);
      setAiType("alert");
      setAiDrawerOpen(true);
    } catch {
      window.alert("Failed to run AI triage on this alert.");
    } finally {
      setAiLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="soc-page" style={{ padding: 32, textAlign: "center" }}>
        <div style={{ color: "var(--color-text-muted)" }}>Loading target investigation cockpit…</div>
      </div>
    );
  }

  if (error || !cockpit?.target) {
    return (
      <div className="soc-page" style={{ padding: 32 }}>
        <div className="surface" style={{ padding: 24, border: "1px solid #e53935", borderRadius: 8 }}>
          <h3 style={{ color: "#ef5350", marginTop: 0 }}>Error Loading Target</h3>
          <p>{error || "Target not found."}</p>
          <Button variant="secondary" onClick={() => navigate("/webscan/targets")}>
            ← Back to All Targets
          </Button>
        </div>
      </div>
    );
  }

  const { target, findings, scans, attack_surface, correlated_alerts } = cockpit;

  const filteredFindings = findings.filter((f) => {
    if (findingFilter === "ALL") return true;
    return f.severity.toUpperCase() === findingFilter.toUpperCase();
  });

  return (
    <div className="soc-page" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Breadcrumb & Navigation */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "0.88rem" }}>
          <Link to="/webscan/targets" style={{ color: "#56c6ff", textDecoration: "none" }}>
            ← Web Targets
          </Link>
          <span style={{ color: "var(--color-text-muted)" }}>/</span>
          <span style={{ color: "#fff", fontWeight: 600 }}>{target.name}</span>
          <Badge tone={(target.authorization_status || "").toUpperCase() === "AUTHORIZED" ? "ok" : "warn"}>
            {target.authorization_status}
          </Badge>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          {(target.authorization_status || "").toUpperCase() !== "AUTHORIZED" && canRun && (
            <Button size="sm" variant="secondary" onClick={handleAuthorize}>
              Authorize Scanning
            </Button>
          )}
          {canRun && (
            <Button
              size="sm"
              variant="primary"
              disabled={scanBusy || (target.authorization_status || "").toUpperCase() !== "AUTHORIZED"}
              onClick={() => handleRunScan("QUICK")}
            >
              {scanBusy ? "Starting Scan…" : "⚡ Quick Scan"}
            </Button>
          )}
        </div>
      </div>

      {/* Target Cockpit Banner Card */}
      <div
        className="surface"
        style={{
          padding: 24,
          borderRadius: 12,
          border: "1px solid rgba(86, 198, 255, 0.25)",
          background: "linear-gradient(135deg, rgba(14, 42, 66, 0.8) 0%, rgba(9, 24, 38, 0.95) 100%)",
        }}
      >
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
          <div>
            <div style={{ fontSize: "0.75rem", color: "#56c6ff", textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.08em" }}>
              Dedicated Target Investigation Cockpit
            </div>
            <h1 style={{ margin: "4px 0 8px 0", fontSize: "1.6rem", color: "#fff", fontFamily: "var(--font-display)" }}>
              {target.name}
            </h1>
            <a
              href={target.url}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "#90caf9", fontSize: "0.95rem", textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 6 }}
            >
              <code>{target.url}</code> ↗
            </a>
          </div>

          {/* Quick Metrics */}
          <div style={{ display: "flex", gap: 20 }}>
            <div style={{ textAlign: "center", padding: "10px 16px", background: "rgba(0,0,0,0.3)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>OVERALL RISK</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "bold", color: target.risk_score > 70 ? "#ef5350" : target.risk_score > 40 ? "#ffa726" : "#66bb6a" }}>
                {target.risk_score} <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>/100</span>
              </div>
            </div>
            <div style={{ textAlign: "center", padding: "10px 16px", background: "rgba(0,0,0,0.3)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>FINDINGS</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "bold", color: "#56c6ff" }}>
                {findings.length}
              </div>
            </div>
            <div style={{ textAlign: "center", padding: "10px 16px", background: "rgba(0,0,0,0.3)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>SIEM ALERTS</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "bold", color: correlated_alerts.length > 0 ? "#ffa726" : "#81c784" }}>
                {correlated_alerts.length}
              </div>
            </div>
            <div style={{ textAlign: "center", padding: "10px 16px", background: "rgba(0,0,0,0.3)", borderRadius: 8, border: "1px solid rgba(255,255,255,0.08)" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>ENDPOINTS</div>
              <div style={{ fontSize: "1.4rem", fontWeight: "bold", color: "#fff" }}>
                {attack_surface.length}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Target Cockpit Sub-Tabs */}
      <div style={{ display: "flex", gap: 12, borderBottom: "1px solid rgba(86, 198, 255, 0.2)", paddingBottom: 8 }}>
        <button
          onClick={() => setActiveTab("findings")}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: activeTab === "findings" ? "#56c6ff" : "transparent",
            color: activeTab === "findings" ? "#041019" : "var(--color-text-muted)",
            fontWeight: 700,
            cursor: "pointer",
            fontSize: "0.88rem",
          }}
        >
          Findings & Vulnerabilities ({findings.length})
        </button>
        <button
          onClick={() => setActiveTab("alerts")}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: activeTab === "alerts" ? "#56c6ff" : "transparent",
            color: activeTab === "alerts" ? "#041019" : "var(--color-text-muted)",
            fontWeight: 700,
            cursor: "pointer",
            fontSize: "0.88rem",
          }}
        >
          Correlated SIEM Alerts ({correlated_alerts.length})
        </button>
        <button
          onClick={() => setActiveTab("endpoints")}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: activeTab === "endpoints" ? "#56c6ff" : "transparent",
            color: activeTab === "endpoints" ? "#041019" : "var(--color-text-muted)",
            fontWeight: 700,
            cursor: "pointer",
            fontSize: "0.88rem",
          }}
        >
          Discovered Endpoints ({attack_surface.length})
        </button>
        <button
          onClick={() => setActiveTab("scans")}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: activeTab === "scans" ? "#56c6ff" : "transparent",
            color: activeTab === "scans" ? "#041019" : "var(--color-text-muted)",
            fontWeight: 700,
            cursor: "pointer",
            fontSize: "0.88rem",
          }}
        >
          Scan History ({scans.length})
        </button>
        <button
          onClick={() => setActiveTab("graph")}
          style={{
            padding: "8px 16px",
            borderRadius: 6,
            border: "none",
            background: activeTab === "graph" ? "#56c6ff" : "transparent",
            color: activeTab === "graph" ? "#041019" : "var(--color-text-muted)",
            fontWeight: 700,
            cursor: "pointer",
            fontSize: "0.88rem",
          }}
        >
          🕸️ Blast Radius Graph
        </button>
      </div>

      {/* TAB 1: FINDINGS FOR THIS TARGET */}
      {activeTab === "findings" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Severity Filter Chips */}
          <div style={{ display: "flex", gap: 8 }}>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => (
              <button
                key={sev}
                onClick={() => setFindingFilter(sev)}
                style={{
                  padding: "4px 12px",
                  borderRadius: 20,
                  border: "1px solid rgba(86, 198, 255, 0.2)",
                  background: findingFilter === sev ? "rgba(86, 198, 255, 0.25)" : "rgba(0,0,0,0.2)",
                  color: findingFilter === sev ? "#56c6ff" : "var(--color-text-muted)",
                  fontSize: "0.78rem",
                  cursor: "pointer",
                  fontWeight: 600,
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          {filteredFindings.length === 0 ? (
            <div className="surface" style={{ padding: 32, textAlign: "center", borderRadius: 8 }}>
              <div style={{ color: "var(--color-text-muted)" }}>No vulnerabilities recorded for this target filter.</div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {filteredFindings.map((f) => (
                <div
                  key={f.id}
                  className="surface"
                  style={{
                    padding: "16px 20px",
                    borderRadius: 8,
                    border: "1px solid rgba(86, 198, 255, 0.15)",
                    display: "flex",
                    flexWrap: "wrap",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 16,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 260 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                      <Badge
                        tone={
                          f.severity === "CRITICAL" || f.severity === "HIGH"
                            ? "danger"
                            : f.severity === "MEDIUM"
                            ? "warn"
                            : "info"
                        }
                      >
                        {f.severity}
                      </Badge>
                      <span style={{ fontWeight: 700, color: "#fff", fontSize: "0.95rem" }}>{f.title}</span>
                      {f.cve_id && <Badge tone="info">{f.cve_id}</Badge>}
                      {f.cwe_id && <span style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>{f.cwe_id}</span>}
                    </div>
                    <div style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                      <code>{f.method} {f.url}</code>
                      {f.param ? <span> · Param: <code>{f.param}</code></span> : null}
                    </div>
                    {f.solution && (
                      <div style={{ fontSize: "0.8rem", color: "#c8e6c9", marginTop: 6 }}>
                        💡 <b>Fix:</b> {f.solution}
                      </div>
                    )}
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={aiLoading}
                      onClick={() => triggerFindingAi(f)}
                      style={{
                        borderColor: "rgba(86, 198, 255, 0.4)",
                        color: "#56c6ff",
                      }}
                    >
                      🤖 AI Triage & WAF Rule
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: CORRELATED SIEM ALERTS */}
      {activeTab === "alerts" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
            Live SIEM detection alerts matching target hostname or host name:
          </div>

          {correlated_alerts.length === 0 ? (
            <div className="surface" style={{ padding: 32, textAlign: "center", borderRadius: 8 }}>
              <div style={{ color: "#81c784" }}>✓ No security incidents detected for this target in telemetry.</div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {correlated_alerts.map((a) => (
                <div
                  key={a.id}
                  className="surface"
                  style={{
                    padding: "16px 20px",
                    borderRadius: 8,
                    border: "1px solid rgba(86, 198, 255, 0.15)",
                    display: "flex",
                    flexWrap: "wrap",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 16,
                  }}
                >
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                      <Badge tone={a.severity === "CRITICAL" || a.severity === "HIGH" ? "danger" : "warn"}>
                        {a.severity}
                      </Badge>
                      <span style={{ fontWeight: 700, color: "#fff", fontSize: "0.95rem" }}>{a.description}</span>
                      <span style={{ fontSize: "0.78rem", color: "var(--color-text-muted)" }}>
                        Tactic: {a.tactic} ({a.technique_id})
                      </span>
                    </div>
                    <div style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                      Host: <code>{a.host}</code> · Time: {a.timestamp || "Recent"} · Risk Score: <b>{a.risk_score}/100</b>
                    </div>
                  </div>

                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={aiLoading}
                    onClick={() => triggerAlertAi(a)}
                    style={{ borderColor: "rgba(86, 198, 255, 0.4)", color: "#56c6ff" }}
                  >
                    🤖 AI Triage & Response
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DISCOVERED ENDPOINTS */}
      {activeTab === "endpoints" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
            Discovered crawl endpoints, web assets, and API routes for this target:
          </div>

          {attack_surface.length === 0 ? (
            <div className="surface" style={{ padding: 32, textAlign: "center", borderRadius: 8 }}>
              <div style={{ color: "var(--color-text-muted)" }}>No endpoints discovered yet. Run a web scan to crawl this asset.</div>
            </div>
          ) : (
            <div className="surface" style={{ borderRadius: 8, overflowX: "auto" }}>
              <table className="table" style={{ width: "100%", margin: 0 }}>
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Discovered URL</th>
                    <th>Status Code</th>
                    <th>Date Discovered</th>
                  </tr>
                </thead>
                <tbody>
                  {attack_surface.map((ep) => (
                    <tr key={ep.id}>
                      <td><code>{ep.method}</code></td>
                      <td>
                        <a href={ep.url} target="_blank" rel="noopener noreferrer" style={{ color: "#90caf9", textDecoration: "none" }}>
                          <code>{ep.url}</code>
                        </a>
                      </td>
                      <td>
                        <Badge tone={ep.status_code < 400 ? "ok" : ep.status_code < 500 ? "warn" : "danger"}>
                          {ep.status_code}
                        </Badge>
                      </td>
                      <td style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                        {ep.discovered_at ? new Date(ep.discovered_at).toLocaleString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: SCAN HISTORY */}
      {activeTab === "scans" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {scans.length === 0 ? (
            <div className="surface" style={{ padding: 32, textAlign: "center", borderRadius: 8 }}>
              <div style={{ color: "var(--color-text-muted)" }}>No previous scans recorded for this target.</div>
            </div>
          ) : (
            <div className="surface" style={{ borderRadius: 8, overflowX: "auto" }}>
              <table className="table" style={{ width: "100%", margin: 0 }}>
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Profile</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Started At</th>
                    <th>Report</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td><code>WAS-#{s.id}</code></td>
                      <td><b>{s.scan_profile}</b></td>
                      <td>
                        {renderScanStatusBadge(s)}
                      </td>
                      <td>{s.findings_count} findings</td>
                      <td style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                        {s.started_at ? new Date(s.started_at).toLocaleString() : "—"}
                      </td>
                      <td>
                        <a
                          href={`/api/webscan/scans/${s.id}/report?format=pdf`}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: "#56c6ff", textDecoration: "none", fontSize: "0.82rem", fontWeight: 600 }}
                        >
                          📄 Download PDF
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 5: ATTACK BLAST RADIUS GRAPH */}
      {activeTab === "graph" && (
        <AttackBlastRadiusGraph
          target={target}
          findings={findings}
          alerts={correlated_alerts}
        />
      )}

      {/* AI Copilot Drawer */}
      <AiTriageDrawer
        isOpen={aiDrawerOpen}
        onClose={() => setAiDrawerOpen(false)}
        data={aiData}
        type={aiType}
      />
    </div>
  );
}

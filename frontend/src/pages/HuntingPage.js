import React, { useEffect, useState } from "react";
import api, { uploadLogFile, purgeEvents, getDatabaseMaintenance, vacuumDatabase } from "../api";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import { hasPermission } from "../auth";
import SigmaRuleStudio from "../components/SigmaRuleStudio";
import MitreAttackMatrix from "../components/MitreAttackMatrix";

const HUNT_PLAYBOOKS = [
  {
    name: "⚡ Suspicious PowerShell",
    query: "powershell",
    desc: "Encoded commands, execution policy bypass, and download cradles.",
  },
  {
    name: "🔑 Credential Access",
    query: "lsass",
    desc: "Memory dumping, Mimikatz artifacts, and SAM registry access.",
  },
  {
    name: "🌐 Lateral Movement",
    query: "psexec",
    desc: "Remote service creation, SMB execution, and WMI invocations.",
  },
  {
    name: "🛡️ Defense Evasion",
    query: "net stop",
    desc: "Disabling security agents, event log clearing, and service tampering.",
  },
  {
    name: "📦 LOLBAS / CertUtil",
    query: "certutil",
    desc: "Living-off-the-land binary exploitation and remote file fetches.",
  },
];

export default function HuntingPage() {
  const [events, setEvents] = useState([]);
  const [q, setQ] = useState("");
  const [ingestion, setIngestion] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [ingesting, setIngesting] = useState(false);

  // Upload modal states
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [uploadError, setUploadError] = useState("");

  // Database Maintenance & Cleanup modal states
  const [showMaintenanceModal, setShowMaintenanceModal] = useState(false);
  const [dbStats, setDbStats] = useState(null);
  const [maintenanceLoading, setMaintenanceLoading] = useState(false);
  const [maintenanceMsg, setMaintenanceMsg] = useState("");

  // Detection Engineering Navigation
  const [activeTab, setActiveTab] = useState("events"); // "events", "studio", "matrix"
  const [studioInitialYaml, setStudioInitialYaml] = useState("");

  const canWrite = hasPermission("events.write");

  const load = async (query = "") => {
    setLoading(true);
    try {
      const path = query ? "/events/search" : "/events";
      const res = await api.get(path, {
        params: query ? { q: query } : { per_page: 100 },
      });
      setEvents(res.data.events || []);
    } catch {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  const loadIngest = async () => {
    try {
      const res = await api.get("/ingestion/status");
      setIngestion(res.data);
    } catch {
      setIngestion(null);
    }
  };

  useEffect(() => {
    load().catch(() => {});
    loadIngest().catch(() => {});
  }, []);

  const runIngest = async () => {
    setIngesting(true);
    try {
      await api.post("/ingestion/run");
      await load(q);
      await loadIngest();
    } finally {
      setIngesting(false);
    }
  };

  const applyPlaybook = (query) => {
    setQ(query);
    load(query);
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setUploadError("Please select a JSON, NDJSON, or log file to upload.");
      return;
    }

    setUploading(true);
    setUploadError("");
    setUploadResult(null);

    try {
      const res = await uploadLogFile(selectedFile);
      setUploadResult(res.data);
      setSelectedFile(null);
      await load(q);
      await loadIngest();
    } catch (err) {
      const errorMsg =
        err.response?.data?.error ||
        err.response?.data?.message ||
        err.message ||
        "Failed to upload and scan log file.";
      setUploadError(typeof errorMsg === "object" ? JSON.stringify(errorMsg) : String(errorMsg));
    } finally {
      setUploading(false);
    }
  };

  const openMaintenanceModal = async () => {
    setShowMaintenanceModal(true);
    setMaintenanceMsg("");
    setMaintenanceLoading(true);
    try {
      const res = await getDatabaseMaintenance();
      setDbStats(res.data);
    } catch {
      setDbStats(null);
    } finally {
      setMaintenanceLoading(false);
    }
  };

  const handlePurgeSingleSource = async (sourceName) => {
    const filename = sourceName.replace("upload:", "");
    if (!window.confirm(`Delete all events ingested from '${filename}'? This will permanently remove them from the database to save space.`)) {
      return;
    }
    try {
      const res = await purgeEvents({ source_name: sourceName });
      window.alert(`Successfully purged ${res.data.deleted_count || 0} events from '${filename}'.`);
      await load(q);
      await loadIngest();
      if (showMaintenanceModal) openMaintenanceModal();
    } catch {
      window.alert("Failed to purge events.");
    }
  };

  const handlePurgeAllUploads = async () => {
    if (!window.confirm("Purge ALL uploaded log file dumps? This will delete all events uploaded via files.")) {
      return;
    }
    setMaintenanceLoading(true);
    try {
      const res = await purgeEvents({ all_uploads: true });
      setMaintenanceMsg(`Purged ${res.data.deleted_count || 0} events across all uploaded files.`);
      await load(q);
      await loadIngest();
      const updated = await getDatabaseMaintenance();
      setDbStats(updated.data);
    } catch {
      setMaintenanceMsg("Failed to purge uploaded logs.");
    } finally {
      setMaintenanceLoading(false);
    }
  };

  const handlePurgeOldLogs = async (days) => {
    if (!window.confirm(`Purge all telemetry logs older than ${days} days?`)) {
      return;
    }
    setMaintenanceLoading(true);
    try {
      const res = await purgeEvents({ older_than_days: days });
      setMaintenanceMsg(`Purged ${res.data.deleted_count || 0} older events.`);
      await load(q);
      await loadIngest();
      const updated = await getDatabaseMaintenance();
      setDbStats(updated.data);
    } catch {
      setMaintenanceMsg("Failed to purge old logs.");
    } finally {
      setMaintenanceLoading(false);
    }
  };

  const handleVacuumDatabase = async () => {
    setMaintenanceLoading(true);
    try {
      const res = await vacuumDatabase();
      setMaintenanceMsg(`Database optimized! Current size: ${res.data.db_size_mb} MB.`);
      const updated = await getDatabaseMaintenance();
      setDbStats(updated.data);
    } catch {
      setMaintenanceMsg("Vacuum failed. Only admin users can execute VACUUM.");
    } finally {
      setMaintenanceLoading(false);
    }
  };

  const exportCsv = () => {
    const headers = ["Timestamp", "Host", "User", "Process", "CommandLine"];
    const rows = events.map((e) => [
      e.timestamp,
      `"${(e.host || "").replace(/"/g, '""')}"`,
      `"${(e.user || "").replace(/"/g, '""')}"`,
      `"${(e.process || "").replace(/"/g, '""')}"`,
      `"${(e.commandline || "").replace(/"/g, '""')}"`,
    ]);
    const csvContent =
      "data:text/csv;charset=utf-8," +
      [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const link = document.createElement("a");
    link.href = encodeURI(csvContent);
    link.download = `threat_hunt_events_${Date.now()}.csv`;
    link.click();
  };

  return (
    <div className="page-shell">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>Threat Hunting &amp; Telemetry Workbench</h1>
          <p className="page-shell__copy">
            Query normalized endpoint telemetry, execute proactive hunting playbooks, upload security log dumps, and manage data lifecycle to keep the database lightweight.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {activeTab === "events" && canWrite ? (
            <Button size="sm" variant="primary" onClick={() => { setShowUploadModal(true); setUploadResult(null); setUploadError(""); }}>
              📤 Upload Log File (JSON)
            </Button>
          ) : null}
          {activeTab === "events" && canWrite ? (
            <Button size="sm" onClick={openMaintenanceModal} title="Database Health and Log Purging">
              🧹 DB Health &amp; Cleanup
            </Button>
          ) : null}
          {activeTab === "events" ? (
            <>
              <Button size="sm" onClick={() => load(q)}>
                ↻ Refresh
              </Button>
              <Button size="sm" onClick={exportCsv} disabled={!events.length}>
                📥 Export CSV
              </Button>
            </>
          ) : null}
        </div>
      </div>

      {/* Detection Engineering & Threat Hunting Sub-Tabs */}
      <div
        style={{
          display: "flex",
          gap: 10,
          borderBottom: "1px solid var(--line)",
          paddingBottom: 14,
          marginBottom: 20,
          marginTop: 18,
          flexWrap: "wrap",
        }}
      >
        <button
          type="button"
          onClick={() => setActiveTab("events")}
          style={{
            background: activeTab === "events" ? "var(--accent, #3ee0a2)" : "var(--bg-2)",
            color: activeTab === "events" ? "#000" : "var(--text)",
            border: activeTab === "events" ? "none" : "1px solid var(--line)",
            fontWeight: 700,
            fontSize: "0.85rem",
            padding: "8px 16px",
            borderRadius: 8,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: 8,
            transition: "all 0.15s ease",
          }}
        >
          🔍 Event Explorer &amp; Playbooks
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("studio")}
          style={{
            background: activeTab === "studio" ? "var(--accent, #3ee0a2)" : "var(--bg-2)",
            color: activeTab === "studio" ? "#000" : "var(--text)",
            border: activeTab === "studio" ? "none" : "1px solid var(--line)",
            fontWeight: 700,
            fontSize: "0.85rem",
            padding: "8px 16px",
            borderRadius: 8,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: 8,
            transition: "all 0.15s ease",
          }}
        >
          ⚡ Sigma Rule Studio &amp; Live Tester
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("matrix")}
          style={{
            background: activeTab === "matrix" ? "var(--accent, #3ee0a2)" : "var(--bg-2)",
            color: activeTab === "matrix" ? "#000" : "var(--text)",
            border: activeTab === "matrix" ? "none" : "1px solid var(--line)",
            fontWeight: 700,
            fontSize: "0.85rem",
            padding: "8px 16px",
            borderRadius: 8,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: 8,
            transition: "all 0.15s ease",
          }}
        >
          🎯 MITRE ATT&amp;CK Matrix
        </button>
      </div>

      {/* TAB 2: SIGMA RULE STUDIO */}
      {activeTab === "studio" && (
        <SigmaRuleStudio
          initialRuleYaml={studioInitialYaml}
          onNavigateToMatrix={() => setActiveTab("matrix")}
        />
      )}

      {/* TAB 3: MITRE ATT&CK MATRIX */}
      {activeTab === "matrix" && (
        <MitreAttackMatrix
          onSelectTechniqueForStudio={(tech) => {
            const yamlTemplate = `title: Custom Detection for ${tech.name}
id: sigma_custom_${tech.id.toLowerCase().replace(/[^a-z0-9]/g, "_")}
status: experimental
description: Custom threat detection rule for MITRE ATT&CK technique ${tech.id} (${tech.name})
level: high
tags:
    - attack.${(tech.tactic_name || "execution").toLowerCase().replace(/\\s+/g, "_")}
    - attack.${tech.id.toLowerCase()}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process: cmd.exe
        commandline:
            - "${tech.id.toLowerCase()}"
    condition: selection
`;
            setStudioInitialYaml(yamlTemplate);
            setActiveTab("studio");
          }}
        />
      )}

      {/* TAB 1: EVENT EXPLORER & PLAYBOOKS */}
      {activeTab === "events" && (
        <>
      {/* HUNTING PLAYBOOKS */}
      <div className="surface" style={{ padding: 14, marginBottom: 16 }}>
        <div className="muted" style={{ fontSize: "0.8rem", textTransform: "uppercase", marginBottom: 8 }}>
          Proactive Threat Hunting Playbooks
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {HUNT_PLAYBOOKS.map((p) => (
            <Button
              key={p.name}
              size="sm"
              variant={q === p.query ? "primary" : undefined}
              onClick={() => applyPlaybook(p.query)}
              title={p.desc}
            >
              {p.name}
            </Button>
          ))}
          {q ? (
            <Button size="sm" onClick={() => applyPlaybook("")}>
              ✕ Reset
            </Button>
          ) : null}
        </div>
      </div>

      {/* INGESTION WATCHER STATUS */}
      <div className="surface" style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10, flexWrap: "wrap", gap: 8 }}>
          <h2 style={{ margin: 0 }}>Log Ingestion Engine</h2>
          {canWrite ? (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <Button size="sm" onClick={() => { setShowUploadModal(true); setUploadResult(null); setUploadError(""); }}>
                📁 Upload JSON Logs
              </Button>
              <Button size="sm" onClick={openMaintenanceModal}>
                🧹 Prune Logs
              </Button>
              <Button size="sm" variant="primary" onClick={runIngest} disabled={ingesting}>
                {ingesting ? "Ingesting…" : "⚡ Run Ingest Cycle"}
              </Button>
            </div>
          ) : null}
        </div>

        {ingestion ? (
          <div>
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
              <div>
                <span className="muted" style={{ fontSize: "0.85rem" }}>Watcher Status: </span>
                <Badge tone={ingestion.watcher?.running ? "ok" : "warn"}>
                  {ingestion.watcher?.running ? "LIVE STREAMING" : "STANDBY"}
                </Badge>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.85rem" }}>Ingestion Cycles: </span>
                <strong>{ingestion.watcher?.cycle_count || 0}</strong>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.85rem" }}>Last Error: </span>
                <span className="muted">{ingestion.watcher?.last_error || "none"}</span>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10 }}>
              {(ingestion.sources || []).map((s) => (
                <div
                  key={s.source}
                  style={{
                    padding: "10px 12px",
                    background: "rgba(255, 255, 255, 0.02)",
                    border: "1px solid var(--line, rgba(255, 255, 255, 0.08))",
                    borderRadius: 6,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 6 }}>
                    <div style={{ fontWeight: 600, fontSize: "0.85rem", wordBreak: "break-all" }}>{s.source}</div>
                    {canWrite && s.source.startsWith("upload:") ? (
                      <button
                        onClick={() => handlePurgeSingleSource(s.source)}
                        style={{
                          background: "transparent",
                          border: "none",
                          color: "var(--danger, #ff5c7a)",
                          cursor: "pointer",
                          fontSize: "0.85rem",
                          padding: "0 2px",
                        }}
                        title="Delete this uploaded log file and its events"
                      >
                        🗑️
                      </button>
                    ) : null}
                  </div>
                  <div className="muted" style={{ fontSize: "0.78rem", marginTop: 4 }}>
                    Status: <Badge tone="ok">{s.status}</Badge> · {s.event_count} events
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="muted">Loading ingestion status…</div>
        )}
      </div>

      {/* TELEMETRY SEARCH & RESULTS */}
      <div className="surface" style={{ padding: 16 }}>
        <form
          style={{ display: "flex", gap: 8, marginBottom: 14 }}
          onSubmit={(e) => {
            e.preventDefault();
            load(q);
          }}
        >
          <input
            className="field__input"
            placeholder="Search host, user, process name, commandline arguments..."
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <Button type="submit" variant="primary">
            Hunt
          </Button>
        </form>

        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, flexWrap: "wrap", gap: 8 }}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>
            Telemetry Events ({events.length} results)
          </span>
          <span className="muted" style={{ fontSize: "0.8rem" }}>
            Click any row to inspect full telemetry artifact
          </span>
        </div>

        {loading ? (
          <div className="muted">Running hunt query…</div>
        ) : !events.length ? (
          <div className="muted">No telemetry events matching query.</div>
        ) : (
          <div style={{ maxHeight: 500, overflowY: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Host</th>
                  <th>User</th>
                  <th>Process</th>
                  <th>Command Line Execution</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr
                    key={e.id}
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelectedEvent(e)}
                  >
                    <td style={{ whiteSpace: "nowrap", fontSize: "0.8rem" }} className="muted">
                      {e.timestamp}
                    </td>
                    <td><code>{e.host}</code></td>
                    <td><strong>{e.user}</strong></td>
                    <td><code>{e.process}</code></td>
                    <td style={{ maxWidth: 380, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      <code style={{ fontSize: "0.78rem" }}>{e.commandline || "—"}</code>
                    </td>
                    <td>
                      <Button size="sm" onClick={(evt) => { evt.stopPropagation(); setSelectedEvent(e); }}>
                        View
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      </>
      )}

      {/* EVENT DETAIL INSPECTOR MODAL */}
      {selectedEvent ? (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: 16,
          }}
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="surface"
            style={{ width: "100%", maxWidth: 640, padding: 24, borderRadius: 10, maxHeight: "90vh", overflowY: "auto" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>EVENT FORENSIC DETAIL</span>
                <h2 style={{ margin: "4px 0" }}>Process Execution: {selectedEvent.process}</h2>
              </div>
              <Button size="sm" onClick={() => setSelectedEvent(null)}>✕ Close</Button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Timestamp:</span>
                <div>{selectedEvent.timestamp}</div>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Host Asset:</span>
                <div><code>{selectedEvent.host}</code></div>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>User Context:</span>
                <div><code>{selectedEvent.user}</code></div>
              </div>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem" }}>Source File:</span>
                <div>{selectedEvent.source || selectedEvent.source_name || "Sysmon / Security Event Log"}</div>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div className="muted" style={{ fontSize: "0.8rem", marginBottom: 4 }}>Full Command Line:</div>
              <pre
                style={{
                  background: "#03070d",
                  padding: 12,
                  borderRadius: 6,
                  border: "1px solid var(--line, #222)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  fontSize: "0.82rem",
                  color: "var(--accent, #3ee0a2)",
                }}
              >
                {selectedEvent.commandline || "—"}
              </pre>
            </div>

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <Button
                size="sm"
                onClick={() => {
                  navigator.clipboard?.writeText(selectedEvent.commandline || "");
                  window.alert("Command line copied to clipboard!");
                }}
              >
                📋 Copy Command
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  navigator.clipboard?.writeText(JSON.stringify(selectedEvent, null, 2));
                  window.alert("JSON event payload copied to clipboard!");
                }}
              >
                📄 Copy Full JSON
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {/* UPLOAD LOG FILE MODAL */}
      {showUploadModal ? (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: 16,
          }}
          onClick={() => setShowUploadModal(false)}
        >
          <div
            className="surface"
            style={{ width: "100%", maxWidth: 560, padding: 24, borderRadius: 12, maxHeight: "90vh", overflowY: "auto" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem", textTransform: "uppercase" }}>TELEMETRY INGESTION</span>
                <h2 style={{ margin: "4px 0" }}>Upload Log File for Scanning</h2>
              </div>
              <Button size="sm" onClick={() => setShowUploadModal(false)}>✕ Close</Button>
            </div>

            <p className="muted" style={{ fontSize: "0.85rem", marginTop: 0, marginBottom: 16, lineHeight: 1.5 }}>
              Upload your security log dumps (.json, .ndjson, .jsonl, .log). DecodeX will normalize the events, correlate against active Sigma detection rules &amp; IOCs, and generate live alerts.
            </p>

            {uploadError ? (
              <div style={{ padding: "10px 14px", background: "rgba(255, 92, 122, 0.12)", border: "1px solid var(--danger, #ff5c7a)", borderRadius: 6, marginBottom: 14, color: "var(--danger, #ff5c7a)", fontSize: "0.85rem" }}>
                {uploadError}
              </div>
            ) : null}

            {uploadResult ? (
              <div style={{ padding: "12px 16px", background: "rgba(62, 224, 162, 0.1)", border: "1px solid var(--ok, #3ee0a2)", borderRadius: 8, marginBottom: 16 }}>
                <div style={{ fontWeight: 600, color: "var(--ok, #3ee0a2)", marginBottom: 6 }}>
                  ✅ Log Ingestion &amp; Threat Scan Complete!
                </div>
                <div style={{ fontSize: "0.85rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                  <div><strong>File:</strong> <code>{uploadResult.filename}</code></div>
                  <div><strong>Events Ingested:</strong> <span style={{ color: "var(--accent, #3ee0a2)", fontWeight: 700 }}>+{uploadResult.events_added}</span></div>
                  <div><strong>Duplicates Skipped:</strong> {uploadResult.events_skipped}</div>
                  <div>
                    <strong>Threat Alerts Generated:</strong>{" "}
                    <span style={{ color: uploadResult.alerts_generated > 0 ? "var(--danger, #ff5c7a)" : "var(--ok, #3ee0a2)", fontWeight: 700 }}>
                      {uploadResult.alerts_generated}
                    </span>
                  </div>
                </div>
              </div>
            ) : null}

            <form onSubmit={handleFileUpload} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div
                style={{
                  border: "2px dashed var(--line-strong, rgba(148, 197, 184, 0.3))",
                  borderRadius: 8,
                  padding: "24px 16px",
                  textAlign: "center",
                  background: "rgba(0, 0, 0, 0.2)",
                  cursor: "pointer",
                }}
                onClick={() => document.getElementById("log-file-input")?.click()}
              >
                <div style={{ fontSize: "2rem", marginBottom: 8 }}>📄</div>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>
                  {selectedFile ? selectedFile.name : "Click or Drag & Drop Log File Here"}
                </div>
                <div className="muted" style={{ fontSize: "0.8rem" }}>
                  {selectedFile
                    ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                    : "Supports JSON arrays, newline-delimited JSON (.ndjson / .jsonl), or syslog (.log)"}
                </div>
                <input
                  id="log-file-input"
                  type="file"
                  accept=".json,.jsonl,.ndjson,.log,.txt"
                  style={{ display: "none" }}
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                      setUploadError("");
                      setUploadResult(null);
                    }
                  }}
                />
              </div>

              {/* FORMAT SAMPLE ACCORDION / HINT */}
              <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "10px 14px", borderRadius: 6, border: "1px solid var(--line, rgba(255,255,255,0.06))" }}>
                <div className="muted" style={{ fontSize: "0.78rem", fontWeight: 600, textTransform: "uppercase", marginBottom: 4 }}>
                  Expected JSON Format Example:
                </div>
                <pre
                  style={{
                    background: "#03070d",
                    padding: 8,
                    borderRadius: 4,
                    fontSize: "0.75rem",
                    margin: 0,
                    overflowX: "auto",
                    color: "var(--accent, #3ee0a2)",
                  }}
                >
{`[
  {
    "timestamp": "2026-08-29T12:00:00Z",
    "host": "WIN-SRV-01",
    "user": "Administrator",
    "process": "powershell.exe",
    "commandline": "powershell.exe -enc JABzACAAPQ..."
  }
]`}
                </pre>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 8 }}>
                <Button type="button" onClick={() => setShowUploadModal(false)}>
                  {uploadResult ? "Done" : "Cancel"}
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  disabled={uploading || !selectedFile}
                >
                  {uploading ? "Ingesting & Scanning…" : "⚡ Ingest & Scan Logs"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {/* DATABASE MAINTENANCE & LOG PURGING MODAL */}
      {showMaintenanceModal ? (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: 16,
          }}
          onClick={() => setShowMaintenanceModal(false)}
        >
          <div
            className="surface"
            style={{ width: "100%", maxWidth: 620, padding: 24, borderRadius: 12, maxHeight: "90vh", overflowY: "auto" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
              <div>
                <span className="muted" style={{ fontSize: "0.8rem", textTransform: "uppercase" }}>DATABASE HYGIENE &amp; RETENTION</span>
                <h2 style={{ margin: "4px 0" }}>Database Health &amp; Data Cleanup</h2>
              </div>
              <Button size="sm" onClick={() => setShowMaintenanceModal(false)}>✕ Close</Button>
            </div>

            <p className="muted" style={{ fontSize: "0.85rem", marginTop: 0, marginBottom: 16 }}>
              Purge temporary log dumps and compress the database to keep DecodeX fast, lightweight, and healthy.
            </p>

            {maintenanceMsg ? (
              <div style={{ padding: "10px 14px", background: "rgba(62, 224, 162, 0.1)", border: "1px solid var(--ok, #3ee0a2)", borderRadius: 6, marginBottom: 14, color: "var(--ok, #3ee0a2)", fontSize: "0.85rem" }}>
                ✅ {maintenanceMsg}
              </div>
            ) : null}

            {/* LIVE DB STATS */}
            {dbStats ? (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 18 }}>
                <div style={{ background: "rgba(255,255,255,0.03)", padding: 12, borderRadius: 8, textAlign: "center" }}>
                  <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Database Size</div>
                  <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "var(--accent, #3ee0a2)" }}>{dbStats.db_size_mb} MB</div>
                </div>
                <div style={{ background: "rgba(255,255,255,0.03)", padding: 12, borderRadius: 8, textAlign: "center" }}>
                  <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Total Events</div>
                  <div style={{ fontSize: "1.4rem", fontWeight: 700 }}>{dbStats.total_events}</div>
                </div>
                <div style={{ background: "rgba(255,255,255,0.03)", padding: 12, borderRadius: 8, textAlign: "center" }}>
                  <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Total Alerts</div>
                  <div style={{ fontSize: "1.4rem", fontWeight: 700 }}>{dbStats.total_alerts}</div>
                </div>
              </div>
            ) : (
              <div className="muted" style={{ marginBottom: 14 }}>Loading database health metrics…</div>
            )}

            {/* UPLOADED FILES SECTION */}
            <div style={{ marginBottom: 18 }}>
              <div className="muted" style={{ fontSize: "0.8rem", fontWeight: 600, textTransform: "uppercase", marginBottom: 8 }}>
                Uploaded Log Files ({dbStats?.uploaded_sources?.length || 0})
              </div>
              {dbStats?.uploaded_sources?.length ? (
                <div style={{ maxHeight: 180, overflowY: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
                  {dbStats.uploaded_sources.map((u) => (
                    <div
                      key={u.source_name}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "8px 12px",
                        background: "rgba(255, 255, 255, 0.02)",
                        border: "1px solid var(--line, rgba(255, 255, 255, 0.06))",
                        borderRadius: 6,
                      }}
                    >
                      <div>
                        <strong>📄 {u.filename}</strong>
                        <span className="muted" style={{ fontSize: "0.78rem", marginLeft: 8 }}>({u.event_count} events)</span>
                      </div>
                      <Button
                        size="sm"
                        onClick={() => handlePurgeSingleSource(u.source_name)}
                        style={{ color: "var(--danger, #ff5c7a)", borderColor: "rgba(255, 92, 122, 0.4)" }}
                      >
                        🗑️ Delete File
                      </Button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="muted" style={{ fontSize: "0.85rem" }}>No uploaded log files currently consuming space.</div>
              )}
            </div>

            {/* BULK CLEANUP ACTIONS */}
            <div style={{ display: "flex", flexDirection: "column", gap: 8, borderTop: "1px solid var(--line, rgba(255,255,255,0.08))", paddingTop: 14 }}>
              <div className="muted" style={{ fontSize: "0.8rem", fontWeight: 600, textTransform: "uppercase" }}>Bulk Maintenance Actions</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <Button
                  size="sm"
                  disabled={maintenanceLoading || !dbStats?.uploaded_sources?.length}
                  onClick={handlePurgeAllUploads}
                  style={{ color: "var(--danger, #ff5c7a)", borderColor: "rgba(255, 92, 122, 0.4)" }}
                >
                  🗑️ Purge All Uploaded Dumps
                </Button>
                <Button
                  size="sm"
                  disabled={maintenanceLoading}
                  onClick={() => handlePurgeOldLogs(30)}
                >
                  ⏱️ Purge Logs Older Than 30 Days
                </Button>
                <Button
                  size="sm"
                  variant="primary"
                  disabled={maintenanceLoading}
                  onClick={handleVacuumDatabase}
                >
                  ⚡ Compact &amp; Vacuum Database
                </Button>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 20 }}>
              <Button onClick={() => setShowMaintenanceModal(false)}>Close</Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

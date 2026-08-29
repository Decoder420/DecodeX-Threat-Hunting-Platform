import React, { useEffect, useState } from "react";
import api, { uploadLogFile } from "../api";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import { hasPermission } from "../auth";

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
      // Refresh the events list and ingestion status automatically
      await load(q);
      await loadIngest();
    } catch (err) {
      setUploadError(
        err.response?.data?.error || "Failed to upload and scan log file. Please check file format."
      );
    } finally {
      setUploading(false);
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
            Query normalized endpoint telemetry, execute proactive hunting playbooks, upload security log dumps, and monitor real-time ingestion watchers.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {canWrite ? (
            <Button size="sm" variant="primary" onClick={() => { setShowUploadModal(true); setUploadResult(null); setUploadError(""); }}>
              📤 Upload Log File (JSON)
            </Button>
          ) : null}
          <Button size="sm" onClick={() => load(q)}>
            ↻ Refresh
          </Button>
          <Button size="sm" onClick={exportCsv} disabled={!events.length}>
            📥 Export CSV
          </Button>
        </div>
      </div>

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
            <div style={{ display: "flex", gap: 8 }}>
              <Button size="sm" onClick={() => { setShowUploadModal(true); setUploadResult(null); setUploadError(""); }}>
                📁 Upload JSON Logs
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

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
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
                  <div style={{ fontWeight: 600, fontSize: "0.88rem" }}>{s.source}</div>
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
    </div>
  );
}

import React, { useEffect, useState } from "react";
import api from "../api";
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
          <h1>Threat Hunting & Telemetry Workbench</h1>
          <p className="page-shell__copy">
            Query normalized endpoint telemetry, execute proactive hunting playbooks, and monitor real-time ingestion watchers.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
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
            <Button size="sm" variant="primary" onClick={runIngest} disabled={ingesting}>
              {ingesting ? "Ingesting…" : "⚡ Run Ingest Cycle"}
            </Button>
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
                    border: "1px solid var(--line, rgba(255,255,255,0.08))",
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

        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
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
                <div>{selectedEvent.source || "Sysmon / Security Event Log"}</div>
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
    </div>
  );
}

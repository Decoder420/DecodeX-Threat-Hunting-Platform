import React, { useState, useEffect, useRef } from "react";
import Badge from "./ui/Badge";
import Button from "./ui/Button";

const INITIAL_LOGS = [
  { id: "log-1", ts: "17:20:01", source: "vercel", ip: "198.51.100.23", method: "POST", path: "/api/v1/auth/login", status: 401, sev: "WARN", msg: "Invalid credential attempt (brute-force threshold)" },
  { id: "log-2", ts: "17:20:04", source: "syslog", ip: "10.0.0.4", method: "EXEC", path: "/bin/sh", status: 0, sev: "INFO", msg: "Cron job execution: healthcheck.sh" },
  { id: "log-3", ts: "17:20:08", source: "cloudflare", ip: "185.220.101.42", method: "GET", path: "/products?id=1%27%20OR%201=1--", status: 403, sev: "CRITICAL", msg: "WAF Rule Triggered: SQLi pattern in querystring" },
  { id: "log-4", ts: "17:20:12", source: "dast", ip: "127.0.0.1", method: "HEAD", path: "/admin/console", status: 302, sev: "INFO", msg: "Spider crawled endpoint redirected to auth" },
  { id: "log-5", ts: "17:20:15", source: "vercel", ip: "103.251.167.20", method: "POST", path: "/api/ingest/vercel", status: 200, sev: "OK", msg: "Log Drain batch ingested: 12 proxy records" },
];

export default function LiveTelemetryTicker() {
  const [isOpen, setIsOpen] = useState(false);
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [isPaused, setIsPaused] = useState(false);
  const [filterSource, setFilterSource] = useState("ALL");
  const [inspectedLog, setInspectedLog] = useState(null);
  const logContainerRef = useRef(null);

  // Live streaming simulation / interval
  useEffect(() => {
    if (isPaused) return;

    const interval = setInterval(() => {
      const sources = ["vercel", "cloudflare", "syslog", "dast"];
      const src = sources[Math.floor(Math.random() * sources.length)];
      const now = new Date();
      const timeStr = now.toTimeString().split(" ")[0];

      const samplePaths = [
        { method: "GET", path: "/api/health", status: 200, sev: "OK", msg: "Healthcheck ping acknowledged" },
        { method: "POST", path: "/api/auth/token", status: 200, sev: "OK", msg: "OAuth session refreshed" },
        { method: "GET", path: "/wp-login.php", status: 404, sev: "WARN", msg: "Probing unknown PHP admin path" },
        { method: "POST", path: "/api/web-targets/4/scan", status: 200, sev: "INFO", msg: "DAST scanner dispatched crawler worker" },
        { method: "GET", path: "/etc/passwd", status: 400, sev: "CRITICAL", msg: "Path traversal attempt blocked by edge rule" },
      ];

      const chosen = samplePaths[Math.floor(Math.random() * samplePaths.length)];
      const ips = ["198.51.100.23", "185.220.101.42", "103.251.167.20", "194.26.29.112", "10.0.1.15"];

      const newLog = {
        id: `log-${Date.now()}`,
        ts: timeStr,
        source: src,
        ip: ips[Math.floor(Math.random() * ips.length)],
        ...chosen,
      };

      setLogs((prev) => [newLog, ...prev.slice(0, 49)]);
    }, 2800);

    return () => clearInterval(interval);
  }, [isPaused]);

  const filteredLogs = logs.filter((l) => {
    if (filterSource === "ALL") return true;
    return l.source.toLowerCase() === filterSource.toLowerCase();
  });

  return (
    <>
      {/* Persistent Bottom HUD Bar */}
      <div
        style={{
          position: "fixed",
          bottom: 0,
          left: 260, // Align beside sidebar
          right: 0,
          zIndex: 850,
          background: "linear-gradient(180deg, rgba(8, 16, 26, 0.96) 0%, rgba(4, 8, 14, 0.98) 100%)",
          borderTop: "1px solid rgba(86, 198, 255, 0.3)",
          boxShadow: "0 -4px 20px rgba(0, 0, 0, 0.5)",
          padding: "6px 20px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          fontSize: "0.82rem",
          cursor: "pointer",
          backdropFilter: "blur(8px)",
        }}
        onClick={() => setIsOpen(!isOpen)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: "1.1rem" }}>📟</span>
          <strong style={{ color: "#56c6ff", letterSpacing: "0.02em" }}>
            Live Telemetry Stream
          </strong>
          <span style={{ color: "var(--color-text-muted)" }}>•</span>
          <span style={{ color: isPaused ? "#f0b429" : "#3ee0a2", display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: isPaused ? "#f0b429" : "#3ee0a2" }} />
            {isPaused ? "PAUSED" : "STREAMING (18 eps)"}
          </span>
          <span style={{ color: "var(--color-text-muted)" }}>•</span>
          <span style={{ color: "rgba(255, 255, 255, 0.7)", fontFamily: "monospace" }}>
            Latest: [{logs[0]?.source?.toUpperCase()}] {logs[0]?.method} {logs[0]?.path} ({logs[0]?.status})
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Badge tone={isOpen ? "info" : "default"}>
            {isOpen ? "Collapse HUD ▼" : "Expand Stream HUD ▲"}
          </Badge>
        </div>
      </div>

      {/* Slide-Up Expanded Stream Console */}
      {isOpen && (
        <div
          style={{
            position: "fixed",
            bottom: 38,
            left: 260,
            right: 0,
            height: 320,
            zIndex: 849,
            background: "#04080e",
            borderTop: "1px solid rgba(86, 198, 255, 0.25)",
            boxShadow: "0 -12px 36px rgba(0, 0, 0, 0.8)",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* Controls Header */}
          <div
            style={{
              padding: "10px 20px",
              background: "rgba(86, 198, 255, 0.05)",
              borderBottom: "1px solid rgba(86, 198, 255, 0.15)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <Button
                size="sm"
                variant={isPaused ? "primary" : "secondary"}
                onClick={() => setIsPaused(!isPaused)}
              >
                {isPaused ? "▶ Resume Stream" : "⏸ Pause"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setLogs([])}>
                Clear
              </Button>
              <div style={{ display: "flex", gap: 6, marginLeft: 12 }}>
                {["ALL", "VERCEL", "CLOUDFLARE", "SYSLOG", "DAST"].map((src) => (
                  <button
                    key={src}
                    onClick={() => setFilterSource(src)}
                    style={{
                      padding: "4px 10px",
                      borderRadius: 4,
                      border: "1px solid rgba(86, 198, 255, 0.2)",
                      background: filterSource === src ? "rgba(86, 198, 255, 0.25)" : "transparent",
                      color: filterSource === src ? "#56c6ff" : "var(--color-text-muted)",
                      fontSize: "0.72rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    {src}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
              Buffered: {filteredLogs.length} events | Click event row for JSON inspector
            </div>
          </div>

          {/* Logs Table / Stream */}
          <div
            ref={logContainerRef}
            style={{
              flex: 1,
              overflowY: "auto",
              padding: "8px 20px",
              fontFamily: "var(--font-mono, monospace)",
              fontSize: "0.8rem",
              display: "flex",
              flexDirection: "column",
              gap: 4,
            }}
          >
            {filteredLogs.length === 0 ? (
              <div style={{ textAlign: "center", padding: 24, color: "var(--color-text-muted)" }}>
                No events in current buffer.
              </div>
            ) : (
              filteredLogs.map((l) => {
                const isCrit = l.sev === "CRITICAL";
                const isWarn = l.sev === "WARN";
                return (
                  <div
                    key={l.id}
                    onClick={() => setInspectedLog(l)}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "70px 90px 130px 60px 1fr 60px",
                      gap: 12,
                      padding: "4px 8px",
                      borderRadius: 4,
                      background: isCrit ? "rgba(255, 82, 82, 0.12)" : isWarn ? "rgba(240, 180, 41, 0.08)" : "rgba(255, 255, 255, 0.02)",
                      borderLeft: `3px solid ${isCrit ? "#ff5252" : isWarn ? "#f0b429" : "#3ee0a2"}`,
                      cursor: "pointer",
                      alignItems: "center",
                    }}
                  >
                    <span style={{ color: "var(--color-text-muted)" }}>{l.ts}</span>
                    <span style={{ color: "#56c6ff", fontWeight: 600 }}>{l.source.toUpperCase()}</span>
                    <span style={{ color: "#a5d6a7" }}>{l.ip}</span>
                    <span style={{ color: "#ffb74d", fontWeight: 700 }}>{l.method}</span>
                    <span style={{ color: "#fff", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {l.path} — <span style={{ color: "rgba(255, 255, 255, 0.6)" }}>{l.msg}</span>
                    </span>
                    <Badge tone={l.status < 300 ? "ok" : l.status < 400 ? "info" : l.status < 500 ? "warn" : "danger"}>
                      {l.status}
                    </Badge>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* JSON Inspector Modal */}
      {inspectedLog && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 9999,
            background: "rgba(2, 6, 12, 0.8)",
            backdropFilter: "blur(4px)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
          }}
          onClick={() => setInspectedLog(null)}
        >
          <div
            style={{
              width: "100%",
              maxWidth: 560,
              background: "#08101a",
              borderRadius: 12,
              border: "1px solid rgba(86, 198, 255, 0.3)",
              boxShadow: "0 20px 50px rgba(0,0,0,0.8)",
              padding: 24,
              display: "flex",
              flexDirection: "column",
              gap: 16,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ margin: 0, color: "#fff", fontSize: "1.1rem" }}>
                Telemetry Log Event Inspector
              </h3>
              <Badge tone={inspectedLog.sev === "CRITICAL" ? "danger" : "ok"}>
                {inspectedLog.sev}
              </Badge>
            </div>

            <pre
              style={{
                margin: 0,
                padding: 16,
                borderRadius: 8,
                background: "#020509",
                border: "1px solid rgba(255, 255, 255, 0.08)",
                fontSize: "0.82rem",
                color: "#81c784",
                overflowX: "auto",
                fontFamily: "monospace",
                lineHeight: 1.5,
              }}
            >
              {JSON.stringify(inspectedLog, null, 2)}
            </pre>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <Button size="sm" variant="ghost" onClick={() => setInspectedLog(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

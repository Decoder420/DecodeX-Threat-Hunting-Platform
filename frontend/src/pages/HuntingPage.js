import React, { useEffect, useState } from "react";
import api from "../api";
import Button from "../components/ui/Button";
import { hasPermission } from "../auth";

export default function HuntingPage() {
  const [events, setEvents] = useState([]);
  const [q, setQ] = useState("");
  const [ingestion, setIngestion] = useState(null);
  const canWrite = hasPermission("events.write");

  const load = async (query = "") => {
    const path = query ? "/events/search" : "/events";
    const res = await api.get(path, { params: query ? { q: query } : { per_page: 50 } });
    setEvents(res.data.events || []);
  };

  const loadIngest = async () => {
    const res = await api.get("/ingestion/status");
    setIngestion(res.data);
  };

  useEffect(() => {
    load().catch(() => {});
    loadIngest().catch(() => {});
  }, []);

  const runIngest = async () => {
    await api.post("/ingestion/run");
    await load();
    await loadIngest();
  };

  return (
    <div className="page-shell">
      <h1>Threat Hunting</h1>
      <p className="page-shell__copy">
        Search normalized events and monitor real-time log ingestion.
      </p>

      <div className="surface" style={{ padding: 16, marginBottom: 16 }}>
        <h2>Ingestion</h2>
        {ingestion ? (
          <>
            <div className="muted">
              Watcher: {ingestion.watcher?.running ? "LIVE" : "STOPPED"} · cycles{" "}
              {ingestion.watcher?.cycle_count || 0} · last error:{" "}
              {ingestion.watcher?.last_error || "none"}
            </div>
            {(ingestion.sources || []).map((s) => (
              <div key={s.source} className="list-row">
                <strong>{s.source}</strong>
                <span>{s.status}</span>
                <span>events {s.event_count}</span>
                <span>offset {s.offset}</span>
              </div>
            ))}
          </>
        ) : (
          <div className="muted">Loading ingestion status…</div>
        )}
        {canWrite ? (
          <Button size="sm" variant="primary" style={{ marginTop: 10 }} onClick={runIngest}>
            Run ingest cycle
          </Button>
        ) : null}
      </div>

      <div className="surface" style={{ padding: 16 }}>
        <form
          style={{ display: "flex", gap: 8, marginBottom: 12 }}
          onSubmit={(e) => {
            e.preventDefault();
            load(q);
          }}
        >
          <input
            className="field__input"
            placeholder="Search host, user, process, IP, commandline"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <Button type="submit">Search</Button>
        </form>
        <div style={{ maxHeight: 480, overflow: "auto" }}>
          {events.map((e) => (
            <div key={e.id} className="list-row">
              <span>{e.timestamp}</span>
              <strong>{e.host}</strong>
              <span>{e.user}</span>
              <span>{e.process}</span>
              <code style={{ fontSize: 12 }}>{(e.commandline || "").slice(0, 80)}</code>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

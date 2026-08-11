import React, { useEffect, useState } from "react";
import api from "../api";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import { hasPermission } from "../auth";

export default function WebScanPage() {
  const [targets, setTargets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("https://example.com");
  const canRun = hasPermission("webscan.run");

  const load = async () => {
    const [t, f] = await Promise.all([api.get("/web-targets"), api.get("/web-findings")]);
    setTargets(t.data.targets || []);
    setFindings(f.data.findings || []);
  };

  useEffect(() => {
    load().catch(() => {});
  }, []);

  const createTarget = async (e) => {
    e.preventDefault();
    await api.post("/web-targets", { name, url, authorization_status: "PENDING" });
    setName("");
    await load();
  };

  const authorize = async (id) => {
    await api.patch(`/web-targets/${id}`, { authorization_status: "AUTHORIZED" });
    await load();
  };

  const scan = async (id) => {
    if (!window.confirm("Run SAFE authorized scan? No exploitation will be performed.")) return;
    const res = await api.post(`/web-targets/${id}/scan`, { confirm: true });
    window.alert(`Scan ${res.data.status}: ${res.data.findings_count} findings`);
    await load();
  };

  return (
    <div className="page-shell">
      <h1>Web Security Scanner</h1>
      <p className="page-shell__copy">
        Authorized targets only. PassiveSafe checks: TLS, headers, cookies, robots.txt. No exploitation.
      </p>

      {canRun ? (
        <form className="surface" style={{ padding: 16, marginBottom: 16 }} onSubmit={createTarget}>
          <h2>Register target</h2>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <input className="field__input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required />
            <input className="field__input" placeholder="https://..." value={url} onChange={(e) => setUrl(e.target.value)} required />
            <Button type="submit" variant="primary">Add</Button>
          </div>
        </form>
      ) : null}

      <div className="surface" style={{ padding: 16, marginBottom: 16 }}>
        <h2>Targets</h2>
        {targets.map((t) => (
          <div key={t.id} className="list-row">
            <strong>{t.name}</strong>
            <span>{t.url}</span>
            <Badge tone={t.authorization_status === "AUTHORIZED" ? "ok" : "warn"}>
              {t.authorization_status}
            </Badge>
            {canRun && t.authorization_status !== "AUTHORIZED" ? (
              <Button size="sm" onClick={() => authorize(t.id)}>Authorize</Button>
            ) : null}
            {canRun && t.authorization_status === "AUTHORIZED" ? (
              <Button size="sm" variant="primary" onClick={() => scan(t.id)}>Scan</Button>
            ) : null}
          </div>
        ))}
      </div>

      <div className="surface" style={{ padding: 16 }}>
        <h2>Findings</h2>
        {findings.map((f) => (
          <div key={f.id} className="list-row">
            <Badge tone={f.severity}>{f.severity}</Badge>
            <strong>{f.title}</strong>
            <span>risk {f.risk_score}</span>
            <span>{f.category}</span>
          </div>
        ))}
        {!findings.length ? <div className="muted">No web findings yet.</div> : null}
      </div>
    </div>
  );
}

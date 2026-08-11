import React, { useEffect, useState } from "react";
import api, { syncFeeds } from "../api";
import Button from "../components/ui/Button";
import { hasPermission } from "../auth";

export default function IntelligencePage() {
  const [iocs, setIocs] = useState([]);
  const [assets, setAssets] = useState([]);
  const [indicator, setIndicator] = useState("");
  const [type, setType] = useState("ip");
  const canWrite = hasPermission("ioc.write");

  const load = async () => {
    const [iocRes, assetRes] = await Promise.all([
      api.get("/ioc"),
      api.get("/assets"),
    ]);
    setIocs(iocRes.data.iocs || []);
    setAssets(assetRes.data.assets || []);
  };

  useEffect(() => {
    load().catch(() => {});
  }, []);

  const addIoc = async (e) => {
    e.preventDefault();
    await api.post("/ioc", { indicator, type, source: "manual", confidence: 85 });
    setIndicator("");
    await load();
  };

  return (
    <div className="page-shell">
      <h1>Threat Intelligence</h1>
      <p className="page-shell__copy">IOC watchlist, feeds, and asset inventory context.</p>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {canWrite ? (
          <Button size="sm" variant="primary" onClick={() => syncFeeds().then(load)}>
            Sync Feeds
          </Button>
        ) : null}
      </div>

      {canWrite ? (
        <form className="surface" style={{ padding: 16, marginBottom: 16 }} onSubmit={addIoc}>
          <h2>Add IOC</h2>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <select className="field__select" value={type} onChange={(e) => setType(e.target.value)}>
              <option value="ip">IPv4</option>
              <option value="domain">DOMAIN</option>
              <option value="hash">HASH</option>
              <option value="url">URL</option>
            </select>
            <input
              className="field__input"
              placeholder="Indicator value"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              required
            />
            <Button type="submit" variant="primary">Add</Button>
          </div>
        </form>
      ) : null}

      <div className="page-grid-2">
        <div className="surface" style={{ padding: 16 }}>
          <h2>IOCs ({iocs.length})</h2>
          <div style={{ maxHeight: 420, overflow: "auto" }}>
            {iocs.map((i) => (
              <div key={i.id} className="list-row">
                <code>{i.indicator}</code>
                <span>{i.type}</span>
                <span>{i.source}</span>
                <span>conf {i.confidence}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="surface" style={{ padding: 16 }}>
          <h2>Assets ({assets.length})</h2>
          {assets.map((a) => (
            <div key={a.id} className="list-row">
              <strong>{a.hostname}</strong>
              <span>{a.ip}</span>
              <span>{a.asset_type}</span>
              <span>{a.criticality}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

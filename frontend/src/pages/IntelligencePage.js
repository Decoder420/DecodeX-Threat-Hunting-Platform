import React, { useEffect, useState, useMemo } from "react";
import api, { syncFeeds } from "../api";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import { hasPermission } from "../auth";

export default function IntelligencePage() {
  const [iocs, setIocs] = useState([]);
  const [assets, setAssets] = useState([]);
  const [indicator, setIndicator] = useState("");
  const [type, setType] = useState("ip");
  const [iocSearch, setIocSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [syncing, setSyncing] = useState(false);
  const [assetSearch, setAssetSearch] = useState("");

  const canWrite = hasPermission("ioc.write");

  const load = async () => {
    try {
      const [iocRes, assetRes] = await Promise.all([
        api.get("/ioc"),
        api.get("/assets"),
      ]);
      setIocs(iocRes.data.iocs || []);
      setAssets(assetRes.data.assets || []);
    } catch {
      setIocs([]);
      setAssets([]);
    }
  };

  useEffect(() => {
    load().catch(() => {});
  }, []);

  const addIoc = async (e) => {
    e.preventDefault();
    if (!indicator.trim()) return;
    try {
      await api.post("/ioc", {
        indicator: indicator.trim(),
        type,
        source: "manual_analyst",
        confidence: 90,
      });
      setIndicator("");
      await load();
    } catch {
      window.alert("Failed to add IOC.");
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      await syncFeeds();
      await load();
      window.alert("Threat intelligence feeds synced successfully!");
    } catch {
      window.alert("Failed to sync feeds.");
    } finally {
      setSyncing(false);
    }
  };

  const filteredIocs = useMemo(() => {
    return iocs.filter((i) => {
      const matchSearch =
        !iocSearch ||
        i.indicator.toLowerCase().includes(iocSearch.toLowerCase()) ||
        (i.source || "").toLowerCase().includes(iocSearch.toLowerCase());
      const matchType =
        typeFilter === "ALL" ||
        (i.type || "").toLowerCase() === typeFilter.toLowerCase();
      return matchSearch && matchType;
    });
  }, [iocs, iocSearch, typeFilter]);

  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      return (
        !assetSearch ||
        (a.hostname || "").toLowerCase().includes(assetSearch.toLowerCase()) ||
        (a.ip || "").toLowerCase().includes(assetSearch.toLowerCase()) ||
        (a.asset_type || "").toLowerCase().includes(assetSearch.toLowerCase())
      );
    });
  }, [assets, assetSearch]);

  const getReputationUrl = (ioc) => {
    const val = encodeURIComponent(ioc.indicator);
    const t = (ioc.type || "").toLowerCase();
    if (t === "ip") return `https://www.abuseipdb.com/check/${val}`;
    if (t === "domain" || t === "url") return `https://www.virustotal.com/gui/domain/${val}`;
    if (t === "hash") return `https://www.virustotal.com/gui/file/${val}`;
    return `https://www.virustotal.com/gui/search/${val}`;
  };

  return (
    <div className="page-shell">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>Threat Intelligence &amp; Asset Context</h1>
          <p className="page-shell__copy">
            Indicators of Compromise (IOC) watchlist, automated threat feeds, reputation lookups, and internal asset inventory.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {canWrite ? (
            <Button size="sm" variant="primary" onClick={handleSync} disabled={syncing}>
              {syncing ? "Syncing Feeds…" : "⚡ Sync Threat Feeds"}
            </Button>
          ) : null}
          <Button size="sm" onClick={load}>
            ↻ Refresh
          </Button>
        </div>
      </div>

      {/* ADD IOC CARD */}
      {canWrite ? (
        <form className="surface" style={{ padding: 16, marginBottom: 16 }} onSubmit={addIoc}>
          <h2 style={{ margin: "0 0 10px" }}>Register Indicator of Compromise (IOC)</h2>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <select
              className="field__select"
              value={type}
              onChange={(e) => setType(e.target.value)}
              style={{ width: "auto" }}
            >
              <option value="ip">IPv4 Address</option>
              <option value="domain">Domain / FQDN</option>
              <option value="hash">SHA256 / MD5 Hash</option>
              <option value="url">URL</option>
            </select>
            <input
              className="field__input"
              style={{ flex: 1, minWidth: 260 }}
              placeholder="e.g. 185.220.101.5 or evil-domain.com or hash..."
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              required
            />
            <Button type="submit" variant="primary">
              + Add to Watchlist
            </Button>
          </div>
        </form>
      ) : null}

      <div className="page-grid-2" style={{ alignItems: "start" }}>
        {/* IOCS COLUMN */}
        <div className="surface" style={{ padding: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <h2 style={{ margin: 0 }}>Active IOC Watchlist ({filteredIocs.length})</h2>
          </div>

          {/* IOC FILTER */}
          <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
            <input
              className="field__input"
              style={{ flex: 1, minWidth: 160 }}
              placeholder="Filter indicators..."
              value={iocSearch}
              onChange={(e) => setIocSearch(e.target.value)}
            />
            <select
              className="field__input"
              style={{ width: "auto" }}
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <option value="ALL">All Types</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="hash">Hash</option>
              <option value="url">URL</option>
            </select>
          </div>

          {!filteredIocs.length ? (
            <div className="muted">No matching indicators.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 520, overflowY: "auto" }}>
              {filteredIocs.map((i) => (
                <div key={i.id} className="list-row" style={{ padding: "8px 12px" }}>
                  <div style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
                    <code style={{ fontSize: "0.85rem", color: "var(--accent, #3ee0a2)" }}>
                      {i.indicator}
                    </code>
                    <div className="muted" style={{ fontSize: "0.75rem", marginTop: 2 }}>
                      Source: {i.source || "Feed"} · Conf: {i.confidence}%
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                    <Badge>{i.type}</Badge>
                    <a
                      href={getReputationUrl(i)}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        fontSize: "0.75rem",
                        color: "var(--info, #5ec8ff)",
                        textDecoration: "none",
                        padding: "3px 6px",
                        border: "1px solid rgba(94, 200, 255, 0.3)",
                        borderRadius: 4,
                      }}
                      title="Inspect indicator reputation externally"
                    >
                      Reputation ↗
                    </a>
                    <button
                      type="button"
                      style={{
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        color: "var(--text-muted, #8fa3a0)",
                        padding: "2px 4px",
                      }}
                      title="Copy indicator"
                      onClick={() => {
                        navigator.clipboard?.writeText(i.indicator);
                        window.alert("Copied to clipboard!");
                      }}
                    >
                      📋
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ASSETS COLUMN */}
        <div className="surface" style={{ padding: 16 }}>
          <h2 style={{ margin: "0 0 10px" }}>Internal Assets &amp; Scope ({filteredAssets.length})</h2>

          <input
            className="field__input"
            style={{ width: "100%", marginBottom: 12 }}
            placeholder="Filter assets by hostname, IP, role..."
            value={assetSearch}
            onChange={(e) => setAssetSearch(e.target.value)}
          />

          {!filteredAssets.length ? (
            <div className="muted">No matching assets found.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 520, overflowY: "auto" }}>
              {filteredAssets.map((a) => (
                <div key={a.id} className="list-row" style={{ padding: "10px 12px" }}>
                  <div>
                    <strong>{a.hostname}</strong>
                    <div className="muted" style={{ fontSize: "0.78rem" }}>
                      IP: <code>{a.ip}</code> · Type: {a.asset_type || "Server"}
                    </div>
                  </div>
                  <Badge
                    tone={
                      a.criticality === "CRITICAL" || a.criticality === "HIGH"
                        ? "danger"
                        : a.criticality === "MEDIUM"
                        ? "warn"
                        : "ok"
                    }
                  >
                    {a.criticality || "NORMAL"}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

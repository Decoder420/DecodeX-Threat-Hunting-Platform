import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import api, { syncFeeds } from "../api";
import webApi from "../webApi";
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
  const [formMode, setFormMode] = useState("ioc"); // "ioc" | "target"
  const [targetForm, setTargetForm] = useState({
    name: "",
    url: "https://",
    environment: "production",
  });
  const [targetSuccess, setTargetSuccess] = useState("");

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

  const handleCreateTarget = async (e) => {
    e.preventDefault();
    if (!targetForm.name.trim()) return;
    try {
      await webApi.createTarget(targetForm);
      setTargetSuccess(`✓ Target "${targetForm.name}" registered for monitoring!`);
      setTargetForm({ name: "", url: "https://", environment: "production" });
      setTimeout(() => setTargetSuccess(""), 4000);
    } catch (err) {
      window.alert(err.response?.data?.error?.message || "Failed to register target.");
    }
  };

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

      {/* INTEGRATIONS & DIRECT CONNECTIVITY BANNER */}
      <div
        className="surface"
        style={{
          padding: "16px 20px",
          borderRadius: 8,
          marginBottom: 16,
          marginTop: 12,
          background: "linear-gradient(135deg, rgba(14, 42, 66, 0.6) 0%, rgba(9, 24, 38, 0.9) 100%)",
          border: "1px solid rgba(86, 198, 255, 0.25)",
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: "1.4rem" }}>⚡</span>
          <div>
            <div style={{ fontWeight: 700, color: "#fff", fontSize: "0.95rem" }}>
              Direct Telemetry Connectors: Vercel, Cloudflare, AWS &amp; Syslog
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
              Stream runtime edge logs, WAF alerts, and adversary activity straight into DecodeX.
            </div>
          </div>
        </div>
        <Link to="/settings" style={{ textDecoration: "none" }}>
          <Button size="sm" variant="ghost" style={{ borderColor: "#56c6ff", color: "#56c6ff" }}>
            Configure Connectors →
          </Button>
        </Link>
      </div>

      {/* ADD IOC OR TARGET CARD */}
      {canWrite ? (
        <div className="surface" style={{ padding: 16, marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 12, borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: 10, marginBottom: 14 }}>
            <button
              onClick={() => setFormMode("ioc")}
              style={{
                background: "transparent",
                border: "none",
                color: formMode === "ioc" ? "#56c6ff" : "var(--color-text-muted)",
                fontWeight: 700,
                fontSize: "0.92rem",
                cursor: "pointer",
                borderBottom: formMode === "ioc" ? "2px solid #56c6ff" : "2px solid transparent",
                paddingBottom: 4,
              }}
            >
              + Register Threat Indicator (IOC)
            </button>
            <button
              onClick={() => setFormMode("target")}
              style={{
                background: "transparent",
                border: "none",
                color: formMode === "target" ? "#56c6ff" : "var(--color-text-muted)",
                fontWeight: 700,
                fontSize: "0.92rem",
                cursor: "pointer",
                borderBottom: formMode === "target" ? "2px solid #56c6ff" : "2px solid transparent",
                paddingBottom: 4,
              }}
            >
              + Quick-Register Monitored Target Asset
            </button>
          </div>

          {targetSuccess && (
            <div style={{ fontSize: "0.85rem", color: "#81c784", marginBottom: 12 }}>
              {targetSuccess}
            </div>
          )}

          {formMode === "ioc" ? (
            <form onSubmit={addIoc} style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
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
            </form>
          ) : (
            <form onSubmit={handleCreateTarget} style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <input
                className="field__input"
                placeholder="Target Name (e.g. Vercel WebApp, Prod API)..."
                value={targetForm.name}
                onChange={(e) => setTargetForm({ ...targetForm, name: e.target.value })}
                style={{ flex: 1, minWidth: 200 }}
                required
              />
              <input
                className="field__input"
                placeholder="https://app.example.com"
                value={targetForm.url}
                onChange={(e) => setTargetForm({ ...targetForm, url: e.target.value })}
                style={{ flex: 1, minWidth: 220 }}
                required
              />
              <select
                className="field__select"
                value={targetForm.environment}
                onChange={(e) => setTargetForm({ ...targetForm, environment: e.target.value })}
                style={{ width: "auto" }}
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="lab">Lab</option>
              </select>
              <Button type="submit" variant="primary">
                + Register Target
              </Button>
            </form>
          )}
        </div>
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

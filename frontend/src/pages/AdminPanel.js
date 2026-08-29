import React, { useEffect, useState } from "react";
import api, { getAdminData, syncFeeds } from "../api";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";

export default function AdminPanel() {
  const [adminData, setAdminData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sigmaFile, setSigmaFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [suppression, setSuppression] = useState({
    name: "",
    rule_id: "",
    field_name: "host",
    field_value: "",
    reason: "",
  });

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await getAdminData();
      setAdminData(res.data);
    } catch {
      setAdminData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSigmaUpload = async (e) => {
    e.preventDefault();
    if (!sigmaFile) return;
    setUploading(true);
    const formData = new FormData();
    formData.append("sigma_file", sigmaFile);
    try {
      const res = await api.post("/sigma", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      window.alert(`Sigma Import Success! Loaded ${res.data.imported || 0} detection rules.`);
      setSigmaFile(null);
      loadData();
    } catch {
      window.alert("Sigma upload failed. Ensure the file is a valid YAML Sigma rule.");
    } finally {
      setUploading(false);
    }
  };

  const handleSuppressionSubmit = async (e) => {
    e.preventDefault();
    if (!suppression.field_value) return;
    try {
      await api.post("/suppression", suppression);
      window.alert("Suppression rule activated successfully.");
      setSuppression({
        name: "",
        rule_id: "",
        field_name: "host",
        field_value: "",
        reason: "",
      });
      loadData();
    } catch {
      window.alert("Failed to save suppression rule.");
    }
  };

  const handleIocSync = async () => {
    setSyncing(true);
    try {
      await syncFeeds();
      window.alert("Threat Intelligence feeds synced successfully!");
      loadData();
    } catch {
      window.alert("Sync failed.");
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="page-shell">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>SOC Administration &amp; Defense Tuning</h1>
          <p className="page-shell__copy">
            Manage detection engineering pipelines, import Sigma detection packages, tune false-positive suppressions, and sync threat intelligence.
          </p>
        </div>
        <Button size="sm" onClick={loadData}>
          ↻ Refresh
        </Button>
      </div>

      {/* SYSTEM ENGINE STATUS TILES */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: 14,
          marginBottom: 18,
        }}
      >
        <div className="surface" style={{ padding: 16, borderRadius: 8, borderLeft: "3px solid var(--ok, #3ee0a2)" }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>YARA Engine</div>
          <div style={{ fontSize: "1.3rem", fontWeight: 700, margin: "4px 0" }}>ACTIVE</div>
          <div className="muted" style={{ fontSize: "0.8rem" }}>Binary pattern matching &amp; malware signature engine</div>
        </div>
        <div className="surface" style={{ padding: 16, borderRadius: 8, borderLeft: "3px solid var(--info, #5ec8ff)" }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Sigma Detection Rules</div>
          <div style={{ fontSize: "1.3rem", fontWeight: 700, margin: "4px 0" }}>READY</div>
          <div className="muted" style={{ fontSize: "0.8rem" }}>Behavioral MITRE-mapped log correlation</div>
        </div>
        <div className="surface" style={{ padding: 16, borderRadius: 8, borderLeft: "3px solid var(--accent-2, #f0b429)" }}>
          <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Threat Intel Feeds</div>
          <div style={{ fontSize: "1.3rem", fontWeight: 700, margin: "4px 0" }}>SYNCHRONIZED</div>
          <div className="muted" style={{ fontSize: "0.8rem" }}>Automated malicious IOC feed ingestion</div>
        </div>
      </div>

      <div className="page-grid-2" style={{ alignItems: "start" }}>
        {/* SIGMA RULE IMPORTER */}
        <div className="surface" style={{ padding: 18 }}>
          <h2 style={{ margin: "0 0 8px" }}>📥 Sigma Detection Package Import</h2>
          <p className="muted" style={{ fontSize: "0.85rem", marginBottom: 14 }}>
            Upload community or proprietary YAML Sigma rules to immediately expand real-time log correlation and automated alert generation.
          </p>
          <form onSubmit={handleSigmaUpload} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <input
              type="file"
              accept=".yml,.yaml"
              onChange={(e) => setSigmaFile(e.target.files[0])}
              style={{
                background: "rgba(0, 0, 0, 0.3)",
                padding: 10,
                borderRadius: 6,
                border: "1px solid var(--line, #333)",
                color: "var(--text, #fff)",
              }}
              required
            />
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <Button type="submit" variant="primary" disabled={uploading || !sigmaFile}>
                {uploading ? "Importing…" : "Upload & Compile Sigma Rules"}
              </Button>
            </div>
          </form>
        </div>

        {/* THREAT INTEL SYNC */}
        <div className="surface" style={{ padding: 18 }}>
          <h2 style={{ margin: "0 0 8px" }}>🛡️ Threat Intelligence Feed Sync</h2>
          <p className="muted" style={{ fontSize: "0.85rem", marginBottom: 14 }}>
            Force an immediate ingestion cycle across external threat feeds (C2 IPs, phishing domains, malware hashes) to update the SOC detection watchlist.
          </p>
          <div style={{ padding: "14px 16px", background: "rgba(255, 255, 255, 0.02)", borderRadius: 6, marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.85rem" }}>
              <span>External Feeds:</span>
              <Badge tone="ok">Online</Badge>
            </div>
          </div>
          <Button variant="primary" onClick={handleIocSync} disabled={syncing}>
            {syncing ? "Syncing Feeds…" : "⚡ Sync Threat Intel Feeds Now"}
          </Button>
        </div>
      </div>

      {/* SUPPRESSION RULES MANAGER */}
      <div className="surface" style={{ padding: 18, marginTop: 18 }}>
        <h2 style={{ margin: "0 0 8px" }}>🔇 False-Positive Suppression Rules</h2>
        <p className="muted" style={{ fontSize: "0.85rem", marginBottom: 14 }}>
          Silence noisy detection alerts matching verified benign hosts, processes, or IP addresses.
        </p>

        <form
          onSubmit={handleSuppressionSubmit}
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            gap: 10,
            marginBottom: 16,
            background: "rgba(255, 255, 255, 0.02)",
            padding: 12,
            borderRadius: 8,
          }}
        >
          <input
            className="field__input"
            placeholder="Rule Label (e.g. Backup Script)"
            value={suppression.name}
            onChange={(e) => setSuppression({ ...suppression, name: e.target.value })}
            required
          />
          <input
            className="field__input"
            placeholder="Rule ID (e.g. sigma-001 or *)"
            value={suppression.rule_id}
            onChange={(e) => setSuppression({ ...suppression, rule_id: e.target.value })}
          />
          <select
            className="field__input"
            value={suppression.field_name}
            onChange={(e) => setSuppression({ ...suppression, field_name: e.target.value })}
          >
            <option value="host">Filter by Host</option>
            <option value="user">Filter by User</option>
            <option value="process">Filter by Process</option>
            <option value="ip">Filter by IP</option>
          </select>
          <input
            className="field__input"
            placeholder="Target Value (e.g. backup-srv-01)"
            value={suppression.field_value}
            onChange={(e) => setSuppression({ ...suppression, field_value: e.target.value })}
            required
          />
          <input
            className="field__input"
            placeholder="Justification reason"
            value={suppression.reason}
            onChange={(e) => setSuppression({ ...suppression, reason: e.target.value })}
          />
          <Button type="submit" variant="primary" style={{ alignSelf: "center" }}>
            + Add Suppression
          </Button>
        </form>

        {/* ACTIVE SUPPRESSIONS LIST */}
        {adminData?.suppressions?.length ? (
          <div style={{ maxHeight: 240, overflowY: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Indicator / Value</th>
                  <th>Reason</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {adminData.suppressions.map((s) => (
                  <tr key={s.id}>
                    <td>#{s.id}</td>
                    <td><code>{s.indicator}</code></td>
                    <td>{s.reason || "Manual suppression rule"}</td>
                    <td><Badge tone={s.active !== false ? "ok" : "warn"}>{s.active !== false ? "ACTIVE" : "DISABLED"}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="muted">No active suppressions configured. All detections will trigger alerts.</div>
        )}
      </div>
    </div>
  );
}
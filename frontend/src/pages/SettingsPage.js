import React, { useEffect, useState } from "react";
import api from "../api";
import Badge from "../components/ui/Badge";
import Button from "../components/ui/Button";
import ProwlerSidePanel from "../components/ProwlerSidePanel";
import { THEMES, getStoredPreferences, saveStoredPreferences, applyTheme } from "../theme";

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("branding");
  const [settings, setSettings] = useState({
    company_name: "DecodeX Security Technologies Private Limited",
    tagline: "Enterprise Threat Hunting & Modern Cloud SIEM",
    timezone: "UTC",
    contact_email: "soc@decodex.internal",
    slack_webhook_url: "",
    discord_webhook_url: "",
    teams_webhook_url: "",
    ai_provider: "builtin",
    ai_api_key_configured: false,
    retention_days: 90,
    compliance_mode: true,
  });

  const [aiKeyInput, setAiKeyInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState("");
  const [testStatus, setTestStatus] = useState("");

  // Platform Preferences & Theme State
  const [preferences, setPreferences] = useState(getStoredPreferences());
  const [prowlerOpen, setProwlerOpen] = useState(false);

  // Ingest Keys State
  const [keys, setKeys] = useState([]);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeySource, setNewKeySource] = useState("vercel");
  const [createdKey, setCreatedKey] = useState(null);
  const [copiedText, setCopiedText] = useState(null);

  const loadSettings = async () => {
    setLoading(true);
    try {
      const [setRes, keyRes] = await Promise.all([
        api.get("/settings"),
        api.get("/admin/ingest_keys"),
      ]);
      setSettings(setRes.data);
      setKeys(keyRes.data.keys || []);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSave = async (e) => {
    if (e) e.preventDefault();
    setSaving(true);
    setSaveStatus("");
    try {
      const payload = { ...settings };
      if (aiKeyInput.trim()) {
        payload.ai_api_key = aiKeyInput.trim();
      }
      await api.put("/settings", payload);
      setSaveStatus("Settings saved successfully!");
      setAiKeyInput("");
      await loadSettings();
    } catch {
      setSaveStatus("Failed to save settings.");
    } finally {
      setSaving(false);
      setTimeout(() => setSaveStatus(""), 4000);
    }
  };

  const handleUpdatePreferences = (changes) => {
    const updated = saveStoredPreferences(changes);
    setPreferences(updated);
    setSaveStatus("Preferences updated!");
    setTimeout(() => setSaveStatus(""), 3000);
  };

  const handleSelectTheme = (themeId) => {
    applyTheme(themeId);
    handleUpdatePreferences({ theme: themeId });
  };

  const handleTestWebhook = async (channel, url) => {
    setTestStatus(`Testing ${channel} webhook…`);
    try {
      const res = await api.post("/settings/notifications/test", { channel, url });
      setTestStatus(`✓ ${res.data.message}`);
    } catch (err) {
      setTestStatus(`✗ ${err.response?.data?.message || "Webhook test failed"}`);
    }
  };

  const handleCreateKey = async (e) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    try {
      const res = await api.post("/api/admin/ingest_keys", {
        name: newKeyName.trim(),
        source: newKeySource,
      });
      setCreatedKey(res.data.key);
      setNewKeyName("");
      await loadSettings();
    } catch {
      window.alert("Failed to create ingestion key.");
    }
  };

  const handleRevokeKey = async (id) => {
    const ok = window.confirm("Are you sure you want to revoke this ingestion key?");
    if (!ok) return;
    try {
      await api.post(`/admin/ingest_keys/${id}/revoke`);
      await loadSettings();
    } catch {
      window.alert("Failed to revoke key.");
    }
  };

  const copyToClipboard = (key, text) => {
    navigator.clipboard.writeText(text);
    setCopiedText(key);
    setTimeout(() => setCopiedText(null), 2500);
  };

  const currentHost = window.location.origin;
  const primaryKey = keys.find((k) => k.is_active)?.key_preview || "thk_live_key";

  if (loading) {
    return (
      <div className="soc-page" style={{ padding: 32, textAlign: "center" }}>
        <div style={{ color: "var(--color-text-muted)" }}>Loading platform configuration…</div>
      </div>
    );
  }

  return (
    <div className="soc-page" style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: "1.6rem", color: "#fff", fontFamily: "var(--font-display)" }}>
            Platform Settings &amp; Integrations
          </h1>
          <div style={{ color: "var(--color-text-muted)", fontSize: "0.88rem", marginTop: 4 }}>
            Customize themes, organization branding, cloud telemetry connectors, and Prowler compliance posture.
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => setProwlerOpen(true)}
            style={{ borderColor: "#56c6ff", color: "#56c6ff" }}
          >
            🛡️ Open Prowler Side Panel
          </Button>
          {saveStatus && (
            <Badge tone={saveStatus.includes("✓") || saveStatus.includes("success") || saveStatus.includes("updated") ? "ok" : "warn"}>
              {saveStatus}
            </Badge>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 10, borderBottom: "1px solid rgba(86, 198, 255, 0.2)", paddingBottom: 8, overflowX: "auto" }}>
        {[
          { id: "branding", label: "🏢 Organization Branding" },
          { id: "themes", label: "🎨 Theme & Appearance" },
          { id: "preferences", label: "⚙️ User & General Settings" },
          { id: "integrations", label: "⚡ Integrations Hub (Vercel, Cloudflare, etc.)" },
          { id: "notifications", label: "🔔 Alert Notifications (Slack/Teams)" },
          { id: "ai", label: "🤖 AI Threat Copilot" },
          { id: "keys", label: "🔑 Ingestion API Keys" },
          { id: "prowler", label: "🛡️ Prowler Posture" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              padding: "10px 18px",
              borderRadius: 6,
              border: "none",
              background: activeTab === t.id ? "#56c6ff" : "transparent",
              color: activeTab === t.id ? "#041019" : "var(--color-text-muted)",
              fontWeight: 700,
              cursor: "pointer",
              fontSize: "0.88rem",
              whiteSpace: "nowrap",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* TAB 1: ORGANIZATION BRANDING */}
      {activeTab === "branding" && (
        <form onSubmit={handleSave} className="surface" style={{ padding: 28, borderRadius: 12, display: "flex", flexDirection: "column", gap: 20 }}>
          <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem" }}>Corporate Identity &amp; Localization</h3>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Organization Legal Name
              </label>
              <input
                className="input"
                type="text"
                value={settings.company_name}
                onChange={(e) => setSettings({ ...settings, company_name: e.target.value })}
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Brand Tagline
              </label>
              <input
                className="input"
                type="text"
                value={settings.tagline}
                onChange={(e) => setSettings({ ...settings, tagline: e.target.value })}
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                SOC Operations Contact Email
              </label>
              <input
                className="input"
                type="email"
                value={settings.contact_email}
                onChange={(e) => setSettings({ ...settings, contact_email: e.target.value })}
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Default Timezone
              </label>
              <select
                className="input"
                value={settings.timezone}
                onChange={(e) => setSettings({ ...settings, timezone: e.target.value })}
                style={{ width: "100%" }}
              >
                <option value="UTC">UTC (Universal Coordinated Time)</option>
                <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
                <option value="America/New_York">America/New_York (EST)</option>
                <option value="Europe/London">Europe/London (GMT/BST)</option>
                <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
              </select>
            </div>
          </div>

          <div style={{ borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: 18 }}>
            <h4 style={{ margin: "0 0 12px 0", color: "#fff", fontSize: "0.95rem" }}>Compliance &amp; Data Retention</h4>
            <div style={{ display: "flex", gap: 24, alignItems: "center", flexWrap: "wrap" }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "0.88rem", color: "#fff", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={settings.compliance_mode}
                  onChange={(e) => setSettings({ ...settings, compliance_mode: e.target.checked })}
                />
                Enable SOC 2 / ISO 27001 Audit Preservation Mode
              </label>
              <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "0.88rem" }}>
                <span style={{ color: "var(--color-text-muted)" }}>Telemetry Retention Window:</span>
                <input
                  type="number"
                  className="input"
                  style={{ width: 80 }}
                  value={settings.retention_days}
                  onChange={(e) => setSettings({ ...settings, retention_days: parseInt(e.target.value, 10) || 90 })}
                />
                <span style={{ color: "var(--color-text-muted)" }}>days</span>
              </div>
            </div>
          </div>

          <div>
            <Button type="submit" variant="primary" disabled={saving}>
              {saving ? "Saving…" : "Save Organization Settings"}
            </Button>
          </div>
        </form>
      )}

      {/* TAB 2: THEME & APPEARANCE */}
      {activeTab === "themes" && (
        <div className="surface" style={{ padding: 28, borderRadius: 12, display: "flex", flexDirection: "column", gap: 20 }}>
          <div>
            <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem" }}>Interface Theme &amp; Visual Style</h3>
            <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)", marginTop: 4 }}>
              Select your preferred visual environment. Themes adapt contrast, HUD reticles, and typography across all SOC pages.
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16 }}>
            {THEMES.map((theme) => {
              const isSelected = (preferences.theme || "emerald") === theme.id;
              return (
                <div
                  key={theme.id}
                  onClick={() => handleSelectTheme(theme.id)}
                  style={{
                    padding: 20,
                    borderRadius: 10,
                    background: theme.bgColor,
                    border: `2px solid ${isSelected ? theme.primaryColor : "rgba(255, 255, 255, 0.1)"}`,
                    cursor: "pointer",
                    boxShadow: isSelected ? `0 0 20px ${theme.primaryColor}33` : "none",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "space-between",
                    gap: 14,
                    transition: "transform 0.15s ease, border-color 0.15s ease",
                  }}
                >
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontWeight: 700, fontSize: "1.05rem", color: isSelected ? theme.primaryColor : "#fff" }}>
                        {theme.name}
                      </span>
                      <Badge tone={isSelected ? "ok" : "info"}>{theme.badge}</Badge>
                    </div>
                    <div style={{ fontSize: "0.82rem", color: "rgba(255, 255, 255, 0.7)", lineHeight: 1.5 }}>
                      {theme.desc}
                    </div>
                  </div>

                  {/* Color Swatch Preview */}
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <div style={{ width: 24, height: 24, borderRadius: 999, background: theme.primaryColor, border: "2px solid #fff" }} />
                    <div style={{ width: 20, height: 20, borderRadius: 999, background: theme.accentColor }} />
                    <div style={{ width: 16, height: 16, borderRadius: 999, background: "rgba(255,255,255,0.2)" }} />
                    <span style={{ fontSize: "0.75rem", color: "rgba(255, 255, 255, 0.5)", marginLeft: "auto" }}>
                      {isSelected ? "Active Theme ✓" : "Click to Apply"}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: USER & GENERAL SETTINGS */}
      {activeTab === "preferences" && (
        <div className="surface" style={{ padding: 28, borderRadius: 12, display: "flex", flexDirection: "column", gap: 24 }}>
          <div>
            <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem" }}>Platform &amp; Analyst Preferences</h3>
            <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)", marginTop: 4 }}>
              Configure navigation defaults, auto-refresh telemetry frequency, audio notifications, and view density.
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Default Landing Workspace
              </label>
              <select
                className="input"
                value={preferences.landingPage}
                onChange={(e) => handleUpdatePreferences({ landingPage: e.target.value })}
                style={{ width: "100%" }}
              >
                <option value="/dashboard">Executive SOC Dashboard (/dashboard)</option>
                <option value="/alerts">Live Detections &amp; Alerts (/alerts)</option>
                <option value="/hunting">Threat Hunting Workspace (/hunting)</option>
                <option value="/webscan">Web Security &amp; DAST Scanner (/webscan)</option>
                <option value="/intelligence">Threat Intelligence &amp; IOCs (/intelligence)</option>
              </select>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Real-Time Telemetry Auto-Refresh Rate
              </label>
              <select
                className="input"
                value={preferences.autoRefreshRate}
                onChange={(e) => handleUpdatePreferences({ autoRefreshRate: e.target.value })}
                style={{ width: "100%" }}
              >
                <option value="off">Off (Manual Refresh)</option>
                <option value="10s">10 Seconds (High Velocity)</option>
                <option value="30s">30 Seconds (Recommended)</option>
                <option value="60s">60 Seconds</option>
                <option value="5m">5 Minutes</option>
              </select>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Session Auto-Timeout / Screen Lock
              </label>
              <select
                className="input"
                value={preferences.sessionTimeout}
                onChange={(e) => handleUpdatePreferences({ sessionTimeout: e.target.value })}
                style={{ width: "100%" }}
              >
                <option value="15m">15 Minutes (Strict Security)</option>
                <option value="30m">30 Minutes</option>
                <option value="60m">1 Hour</option>
                <option value="8h">8 Hours (Full Shift)</option>
                <option value="never">Never</option>
              </select>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                Default Incident Report Export Format
              </label>
              <select
                className="input"
                value={preferences.defaultExportFormat}
                onChange={(e) => handleUpdatePreferences({ defaultExportFormat: e.target.value })}
                style={{ width: "100%" }}
              >
                <option value="pdf">Executive PDF (DecodeX Brand Theme)</option>
                <option value="json">Structured JSON Data</option>
                <option value="csv">Tabular CSV Format</option>
              </select>
            </div>
          </div>

          <div style={{ borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: 18, display: "flex", flexDirection: "column", gap: 14 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: "0.88rem", color: "#fff", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={preferences.compactMode}
                onChange={(e) => handleUpdatePreferences({ compactMode: e.target.checked })}
              />
              <b>Compact Data Table Mode:</b> Use condensed row padding for maximum information density in alerts and logs.
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: "0.88rem", color: "#fff", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={preferences.soundAlerts}
                onChange={(e) => handleUpdatePreferences({ soundAlerts: e.target.checked })}
              />
              <b>Audio Alert Chime:</b> Play audible pulse ping when a CRITICAL threat detection arrives.
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: "0.88rem", color: "#fff", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={preferences.confirmDestructiveActions}
                onChange={(e) => handleUpdatePreferences({ confirmDestructiveActions: e.target.checked })}
              />
              <b>Destructive Action Confirmation:</b> Require confirmation dialogs when deleting targets, revoking API keys, or clearing logs.
            </label>

            <label style={{ display: "flex", alignItems: "center", gap: 10, fontSize: "0.88rem", color: "#fff", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={preferences.anonymizeIps}
                onChange={(e) => handleUpdatePreferences({ anonymizeIps: e.target.checked })}
              />
              <b>Anonymize Telemetry IPs in Public Views:</b> Mask client IP addresses (e.g. <code>198.51.100.***</code>) for privacy and compliance demos.
            </label>
          </div>
        </div>
      )}

      {/* TAB 4: INTEGRATIONS HUB */}
      {activeTab === "integrations" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ fontSize: "0.9rem", color: "var(--color-text-muted)" }}>
            Connect external developer software, cloud providers, and log forwarders directly to DecodeX:
          </div>

          {/* Vercel Card */}
          <div
            className="surface"
            style={{
              padding: 24,
              borderRadius: 12,
              border: "1px solid rgba(86, 198, 255, 0.3)",
              background: "linear-gradient(135deg, rgba(14, 42, 66, 0.6) 0%, rgba(9, 24, 38, 0.9) 100%)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ fontSize: "1.8rem" }}>▲</div>
                <div>
                  <h3 style={{ margin: 0, fontSize: "1.2rem", color: "#fff" }}>Vercel Log Drain Integration</h3>
                  <div style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                    Stream runtime lambdas, edge middleware, and access logs directly into DecodeX.
                  </div>
                </div>
              </div>
              <Badge tone="ok">Ready to Connect</Badge>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <label style={{ fontSize: "0.78rem", color: "#56c6ff", fontWeight: 700, textTransform: "uppercase" }}>
                  Your Vercel Webhook Ingestion URL
                </label>
                <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
                  <input
                    className="input"
                    readOnly
                    value={`${currentHost}/api/ingest/vercel`}
                    style={{ flex: 1, fontFamily: "monospace", color: "#a5d6a7" }}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => copyToClipboard("vercel_url", `${currentHost}/api/ingest/vercel`)}
                  >
                    {copiedText === "vercel_url" ? "✓ Copied!" : "Copy URL"}
                  </Button>
                </div>
              </div>

              <div
                style={{
                  padding: 16,
                  borderRadius: 8,
                  background: "rgba(0, 0, 0, 0.3)",
                  border: "1px solid rgba(255, 255, 255, 0.08)",
                  fontSize: "0.85rem",
                  lineHeight: 1.6,
                }}
              >
                <b>3-Step Setup in Vercel Dashboard:</b>
                <ol style={{ margin: "8px 0 0 20px", padding: 0 }}>
                  <li>Go to your Vercel Project → <b>Settings</b> → <b>Log Drains</b>.</li>
                  <li>Click <b>Add Log Drain</b>, select <b>JSON format</b>, and paste the URL above.</li>
                  <li>
                    Add custom header: <code>X-Ingest-Key: {primaryKey}</code> (or any active key from the{" "}
                    <b>Ingestion Keys</b> tab). DecodeX will immediately start parsing and hunting threats!
                  </li>
                </ol>
              </div>
            </div>
          </div>

          {/* Cloudflare Card */}
          <div className="surface" style={{ padding: 24, borderRadius: 12, border: "1px solid rgba(255, 255, 255, 0.1)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ fontSize: "1.8rem" }}>☁️</div>
                <div>
                  <h3 style={{ margin: 0, fontSize: "1.2rem", color: "#fff" }}>Cloudflare Logpush &amp; WAF Alerts</h3>
                  <div style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                    Receive perimeter attack logs, rate-limit drops, and credential stuffing alerts.
                  </div>
                </div>
              </div>
              <Badge tone="info">Supported</Badge>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <input
                className="input"
                readOnly
                value={`${currentHost}/api/ingest_logs`}
                style={{ flex: 1, fontFamily: "monospace" }}
              />
              <Button size="sm" variant="ghost" onClick={() => copyToClipboard("cf_url", `${currentHost}/api/ingest_logs`)}>
                {copiedText === "cf_url" ? "✓ Copied!" : "Copy URL"}
              </Button>
            </div>
          </div>

          {/* Syslog Card */}
          <div className="surface" style={{ padding: 24, borderRadius: 12, border: "1px solid rgba(255, 255, 255, 0.1)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ fontSize: "1.8rem" }}>📡</div>
                <div>
                  <h3 style={{ margin: 0, fontSize: "1.2rem", color: "#fff" }}>Syslog / Vector / Fluentbit Shipper</h3>
                  <div style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                    Forward Linux, macOS, and firewall telemetry over standard syslog protocols.
                  </div>
                </div>
              </div>
              <Badge tone="info">Endpoint Active</Badge>
            </div>
            <p style={{ margin: 0, fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
              Stream raw RFC 5424 syslog or filebeat events using HTTP POST to <code>{currentHost}/api/ingest_logs</code>.
            </p>
          </div>
        </div>
      )}

      {/* TAB 5: ALERT NOTIFICATIONS */}
      {activeTab === "notifications" && (
        <form onSubmit={handleSave} className="surface" style={{ padding: 28, borderRadius: 12, display: "flex", flexDirection: "column", gap: 20 }}>
          <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem" }}>Live SOC Incident Webhook Dispatchers</h3>
          <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
            Automatically dispatch real-time incident cards to your security operations chat rooms:
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
              Slack Incoming Webhook URL
            </label>
            <div style={{ display: "flex", gap: 10 }}>
              <input
                className="input"
                type="url"
                placeholder="https://hooks.slack.com/services/..."
                value={settings.slack_webhook_url || ""}
                onChange={(e) => setSettings({ ...settings, slack_webhook_url: e.target.value })}
                style={{ flex: 1 }}
              />
              <Button
                type="button"
                size="sm"
                variant="secondary"
                disabled={!settings.slack_webhook_url}
                onClick={() => handleTestWebhook("slack", settings.slack_webhook_url)}
              >
                Test Slack
              </Button>
            </div>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
              Discord Webhook URL
            </label>
            <div style={{ display: "flex", gap: 10 }}>
              <input
                className="input"
                type="url"
                placeholder="https://discord.com/api/webhooks/..."
                value={settings.discord_webhook_url || ""}
                onChange={(e) => setSettings({ ...settings, discord_webhook_url: e.target.value })}
                style={{ flex: 1 }}
              />
              <Button
                type="button"
                size="sm"
                variant="secondary"
                disabled={!settings.discord_webhook_url}
                onClick={() => handleTestWebhook("discord", settings.discord_webhook_url)}
              >
                Test Discord
              </Button>
            </div>
          </div>

          {testStatus && (
            <div style={{ fontSize: "0.85rem", color: testStatus.startsWith("✓") ? "#66bb6a" : "#ef5350" }}>
              {testStatus}
            </div>
          )}

          <div>
            <Button type="submit" variant="primary" disabled={saving}>
              {saving ? "Saving…" : "Save Notification Webhooks"}
            </Button>
          </div>
        </form>
      )}

      {/* TAB 6: AI COPILOT SETTINGS */}
      {activeTab === "ai" && (
        <form onSubmit={handleSave} className="surface" style={{ padding: 28, borderRadius: 12, display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem" }}>DecodeX AI Threat Hunting Engine</h3>
              <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)", marginTop: 4 }}>
                Powers automated incident triage, root cause reasoning, and 1-click firewall rule generation.
              </div>
            </div>
            <Badge tone="ok">Active</Badge>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
              AI Reasoning Provider
            </label>
            <select
              className="input"
              value={settings.ai_provider}
              onChange={(e) => setSettings({ ...settings, ai_provider: e.target.value })}
              style={{ maxWidth: 360 }}
            >
              <option value="builtin">DecodeX Built-in Cyber Engine (Offline, Zero Cost, Zero Dependency)</option>
              <option value="gemini">Google Gemini 1.5 Pro / Flash</option>
              <option value="openai">OpenAI GPT-4o / Mini</option>
            </select>
          </div>

          {settings.ai_provider !== "builtin" && (
            <div>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 6 }}>
                API Secret Key ({settings.ai_provider.toUpperCase()})
              </label>
              <input
                className="input"
                type="password"
                placeholder={settings.ai_api_key_configured ? "•••••••••••••••• (Configured)" : "Paste API Key..."}
                value={aiKeyInput}
                onChange={(e) => setAiKeyInput(e.target.value)}
                style={{ maxWidth: 480 }}
              />
              <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: 4 }}>
                Your key is stored securely in the local database and used solely for threat analysis.
              </div>
            </div>
          )}

          <div
            style={{
              padding: 16,
              borderRadius: 8,
              background: "rgba(86, 198, 255, 0.06)",
              border: "1px solid rgba(86, 198, 255, 0.2)",
              fontSize: "0.85rem",
              lineHeight: 1.6,
            }}
          >
            💡 <b>Built-in Offline Intelligence:</b> DecodeX ships with an expert heuristic cyber engine that operates completely offline, mapping telemetry against MITRE ATT&CK techniques, generating Vercel/Cloudflare blocks, and explaining blast radius with zero external API calls.
          </div>

          <div>
            <Button type="submit" variant="primary" disabled={saving}>
              {saving ? "Saving…" : "Save AI Settings"}
            </Button>
          </div>
        </form>
      )}

      {/* TAB 7: INGESTION KEYS */}
      {activeTab === "keys" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {/* Create Key Form */}
          <form onSubmit={handleCreateKey} className="surface" style={{ padding: 20, borderRadius: 12, display: "flex", gap: 12, alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 4 }}>
                Key Name
              </label>
              <input
                className="input"
                placeholder="e.g. Vercel Production, AWS CloudTrail, Staging..."
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                style={{ width: "100%" }}
              />
            </div>
            <div style={{ width: 160 }}>
              <label style={{ display: "block", fontSize: "0.82rem", color: "var(--color-text-muted)", marginBottom: 4 }}>
                Source Tag
              </label>
              <select
                className="input"
                value={newKeySource}
                onChange={(e) => setNewKeySource(e.target.value)}
                style={{ width: "100%" }}
              >
                <option value="vercel">Vercel</option>
                <option value="cloudflare">Cloudflare</option>
                <option value="aws">AWS</option>
                <option value="github">GitHub</option>
                <option value="syslog">Syslog</option>
                <option value="custom">Custom</option>
              </select>
            </div>
            <Button type="submit" variant="primary">
              Generate Ingest Key
            </Button>
          </form>

          {/* Newly created key banner */}
          {createdKey && (
            <div
              style={{
                padding: 16,
                borderRadius: 8,
                background: "rgba(76, 175, 80, 0.15)",
                border: "1px solid rgba(76, 175, 80, 0.4)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div>
                <div style={{ fontSize: "0.82rem", color: "#a5d6a7", fontWeight: 700 }}>
                  ✓ Ingestion Key Created! Copy it now (it won't be shown again):
                </div>
                <code style={{ fontSize: "1rem", color: "#fff", display: "inline-block", marginTop: 4 }}>
                  {createdKey}
                </code>
              </div>
              <Button size="sm" variant="ghost" onClick={() => copyToClipboard("new_key", createdKey)}>
                {copiedText === "new_key" ? "✓ Copied!" : "Copy Key"}
              </Button>
            </div>
          )}

          {/* Keys Table */}
          <div className="surface" style={{ borderRadius: 12, overflowX: "auto" }}>
            <table className="table" style={{ width: "100%", margin: 0 }}>
              <thead>
                <tr>
                  <th>Key Name</th>
                  <th>Source</th>
                  <th>Key Preview</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: "center", color: "var(--color-text-muted)" }}>
                      No active ingestion keys. Generate one above to connect Vercel or cloud webhooks.
                    </td>
                  </tr>
                ) : (
                  keys.map((k) => (
                    <tr key={k.id}>
                      <td><b>{k.name}</b></td>
                      <td><code>{k.source}</code></td>
                      <td><code>{k.key_preview}</code></td>
                      <td>
                        <Badge tone={k.is_active ? "ok" : "danger"}>
                          {k.is_active ? "Active" : "Revoked"}
                        </Badge>
                      </td>
                      <td style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                        {new Date(k.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        {k.is_active && (
                          <Button size="sm" variant="danger" onClick={() => handleRevokeKey(k.id)}>
                            Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 8: PROWLER POSTURE SUMMARY */}
      {activeTab === "prowler" && (
        <div className="surface" style={{ padding: 28, borderRadius: 12, display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h3 style={{ margin: 0, color: "#fff", fontSize: "1.2rem" }}>Prowler Cloud Security Posture Management (CSPM)</h3>
              <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)", marginTop: 4 }}>
                Automated multi-cloud compliance posture inspection across CIS Benchmarks, SOC 2, ISO 27001, and PCI-DSS.
              </div>
            </div>
            <Button variant="primary" onClick={() => setProwlerOpen(true)}>
              🛡️ Open Prowler Cockpit Panel
            </Button>
          </div>

          <div
            style={{
              padding: 20,
              borderRadius: 8,
              background: "rgba(86, 198, 255, 0.06)",
              border: "1px solid rgba(86, 198, 255, 0.2)",
              fontSize: "0.88rem",
              lineHeight: 1.6,
            }}
          >
            Prowler runs automated checks on cloud perimeters, Vercel deployments, AWS credentials, S3 public access, and edge WAF rules. Click <b>Open Prowler Cockpit Panel</b> to view individual check results, risk assessments, and 1-click remediation scripts!
          </div>
        </div>
      )}

      {/* Prowler Side Panel */}
      <ProwlerSidePanel isOpen={prowlerOpen} onClose={() => setProwlerOpen(false)} />
    </div>
  );
}

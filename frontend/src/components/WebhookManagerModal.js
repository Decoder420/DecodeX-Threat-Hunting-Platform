import React, { useState, useEffect } from "react";
import Button from "./ui/Button";
import Badge from "./ui/Badge";
import { listWebhooks, createWebhook, deleteWebhook, testWebhook } from "../api";
import { hasPermission } from "../auth";

export default function WebhookManagerModal({ isOpen, onClose }) {
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Form states
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [channelType, setChannelType] = useState("discord");
  const [subEvents, setSubEvents] = useState({
    "finding.critical": true,
    "finding.high": true,
    "alert.critical": true,
    "scan.completed": true,
  });
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState(null);
  const [testResult, setTestResult] = useState(null);

  const canWrite = hasPermission("webhooks.write");

  useEffect(() => {
    if (isOpen) {
      load();
    }
  }, [isOpen]);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await listWebhooks();
      setWebhooks(res.data.webhooks || []);
    } catch (err) {
      setError("Failed to load webhook configurations.");
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!name.trim() || !url.trim()) {
      setError("Please provide a webhook name and URL.");
      return;
    }
    setSaving(true);
    setError("");
    setSuccessMsg("");
    try {
      const activeEvents = Object.keys(subEvents).filter((k) => subEvents[k]);
      const payload = {
        name: name.trim(),
        url: url.trim(),
        channel_type: channelType,
        events_subscribed: activeEvents.join(","),
        is_active: true,
      };
      await createWebhook(payload);
      setSuccessMsg(`Webhook '${name}' created successfully!`);
      setName("");
      setUrl("");
      setShowAddForm(false);
      load();
    } catch (err) {
      const msg =
        (err.response && err.response.data && err.response.data.message) ||
        err.message ||
        "Failed creating webhook.";
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id, whName) => {
    if (!window.confirm(`Delete webhook '${whName}'?`)) return;
    try {
      await deleteWebhook(id);
      setSuccessMsg(`Webhook '${whName}' deleted.`);
      load();
    } catch (err) {
      setError("Failed to delete webhook.");
    }
  };

  const handleTestPing = async (whId) => {
    setTestingId(whId);
    setTestResult(null);
    try {
      const res = await testWebhook(whId);
      setTestResult({
        whId,
        delivered: res.data.delivered,
        httpStatus: res.data.http_status,
        response: res.data.response,
      });
    } catch (err) {
      const res = err.response?.data;
      setTestResult({
        whId,
        delivered: false,
        httpStatus: res?.http_status || 0,
        response: res?.response || err.message,
      });
    } finally {
      setTestingId(null);
    }
  };

  if (!isOpen) return null;

  const getChannelIcon = (type) => {
    switch (type) {
      case "discord":
        return "💬 Discord";
      case "slack":
        return "⚡ Slack";
      case "teams":
        return "👥 MS Teams";
      default:
        return "🌐 Custom Webhook";
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: "rgba(0,0,0,0.75)",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        zIndex: 9999,
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: "var(--bg-2)",
          border: "1px solid var(--line)",
          borderRadius: 14,
          maxWidth: 720,
          width: "100%",
          padding: "24px",
          maxHeight: "90vh",
          overflowY: "auto",
          boxShadow: "0 16px 48px rgba(0,0,0,0.6)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            marginBottom: 18,
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: "1.3rem" }}>🔔</span>
              <h2 style={{ margin: 0, fontSize: "1.2rem", fontWeight: 700 }}>
                Webhook Alert Channels
              </h2>
              <Badge tone="ok">Live Dispatch</Badge>
            </div>
            <p
              style={{
                margin: "4px 0 0",
                fontSize: "0.85rem",
                color: "var(--color-text-muted)",
              }}
            >
              Automatically broadcast critical vulnerability detections and SIEM incident cards to Discord, Slack, or MS Teams.
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--color-text-muted)",
              fontSize: "1.2rem",
              cursor: "pointer",
            }}
          >
            ✕
          </button>
        </div>

        {error && (
          <div
            style={{
              padding: "10px 14px",
              background: "rgba(255, 92, 122, 0.1)",
              color: "#ff5c7a",
              borderRadius: 8,
              fontSize: "0.85rem",
              marginBottom: 14,
            }}
          >
            {error}
          </div>
        )}

        {successMsg && (
          <div
            style={{
              padding: "10px 14px",
              background: "rgba(62, 224, 162, 0.1)",
              color: "#3ee0a2",
              borderRadius: 8,
              fontSize: "0.85rem",
              marginBottom: 14,
            }}
          >
            {successMsg}
          </div>
        )}

        {/* Existing Webhooks List */}
        <div style={{ marginBottom: 20 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 10,
            }}
          >
            <span
              style={{
                fontSize: "0.8rem",
                fontWeight: 700,
                textTransform: "uppercase",
                color: "var(--color-text-muted)",
              }}
            >
              Configured Channels ({webhooks.length})
            </span>
            {canWrite && !showAddForm && (
              <Button
                size="sm"
                tone="primary"
                onClick={() => setShowAddForm(true)}
              >
                + Add Webhook
              </Button>
            )}
          </div>

          {loading ? (
            <div style={{ textAlign: "center", padding: 20, color: "var(--color-text-muted)" }}>
              Loading webhooks...
            </div>
          ) : webhooks.length === 0 ? (
            <div
              style={{
                padding: "24px",
                background: "var(--bg-1)",
                border: "1px dashed var(--line)",
                borderRadius: 10,
                textAlign: "center",
                color: "var(--color-text-muted)",
                fontSize: "0.88rem",
              }}
            >
              No notification webhooks configured. Add a Discord or Slack webhook to receive instant alerts.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {webhooks.map((wh) => (
                <div
                  key={wh.id}
                  style={{
                    background: "var(--bg-1)",
                    border: "1px solid var(--line)",
                    borderRadius: 10,
                    padding: "14px 16px",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: 12,
                  }}
                >
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <strong>{wh.name}</strong>
                      <Badge tone="neutral">{getChannelIcon(wh.channel_type)}</Badge>
                      <Badge tone={wh.is_active ? "ok" : "warn"}>
                        {wh.is_active ? "Active" : "Disabled"}
                      </Badge>
                    </div>
                    <div
                      style={{
                        fontFamily: "monospace",
                        fontSize: "0.75rem",
                        color: "var(--color-text-muted)",
                        marginTop: 4,
                      }}
                    >
                      {wh.url.replace(/(https?:\/\/[^/]+\/).*/, "$1••••••••")}
                    </div>
                    <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: 4 }}>
                      Events: <code style={{ color: "#56c6ff" }}>{wh.events_subscribed}</code> • Delivered:{" "}
                      <strong>{wh.delivery_count || 0}</strong>
                    </div>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => handleTestPing(wh.id)}
                      disabled={testingId === wh.id}
                    >
                      {testingId === wh.id ? "Pinging..." : "⚡ Test Ping"}
                    </Button>
                    {canWrite && (
                      <Button
                        size="sm"
                        tone="danger"
                        onClick={() => handleDelete(wh.id, wh.name)}
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Test Ping Result Callout */}
        {testResult && (
          <div
            style={{
              padding: "12px 16px",
              background: testResult.delivered
                ? "rgba(62, 224, 162, 0.1)"
                : "rgba(255, 92, 122, 0.1)",
              border: `1px solid ${testResult.delivered ? "#3ee0a2" : "#ff5c7a"}`,
              borderRadius: 8,
              marginBottom: 16,
              fontSize: "0.85rem",
            }}
          >
            <strong>{testResult.delivered ? "✓ Test Ping Delivered Successfully!" : "⚠️ Test Ping Failed:"}</strong>
            <div style={{ fontFamily: "monospace", fontSize: "0.78rem", marginTop: 4 }}>
              HTTP Status: {testResult.httpStatus || "Connection Failed"} {testResult.response ? `(${testResult.response})` : ""}
            </div>
          </div>
        )}

        {/* Add Webhook Form */}
        {showAddForm && (
          <form
            onSubmit={handleCreate}
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              borderRadius: 10,
              padding: "18px",
              display: "flex",
              flexDirection: "column",
              gap: 14,
            }}
          >
            <div style={{ fontWeight: 700, fontSize: "0.95rem" }}>
              Configure New Webhook Channel
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div>
                <label style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--color-text-muted)" }}>
                  Channel Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. #soc-alerts"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    background: "var(--bg-2)",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    borderRadius: 6,
                    fontSize: "0.85rem",
                  }}
                  required
                />
              </div>

              <div>
                <label style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--color-text-muted)" }}>
                  Channel Type
                </label>
                <select
                  value={channelType}
                  onChange={(e) => setChannelType(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "8px 10px",
                    background: "var(--bg-2)",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    borderRadius: 6,
                    fontSize: "0.85rem",
                  }}
                >
                  <option value="discord">Discord Webhook</option>
                  <option value="slack">Slack Incoming Webhook</option>
                  <option value="teams">Microsoft Teams Connector</option>
                  <option value="generic">Generic JSON HTTP Webhook</option>
                </select>
              </div>
            </div>

            <div>
              <label style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--color-text-muted)" }}>
                Webhook Endpoint URL
              </label>
              <input
                type="url"
                placeholder={
                  channelType === "discord"
                    ? "https://discord.com/api/webhooks/..."
                    : channelType === "slack"
                    ? "https://hooks.slack.com/services/..."
                    : "https://your-server.com/api/webhook"
                }
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                style={{
                  width: "100%",
                  padding: "8px 10px",
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  color: "var(--text)",
                  borderRadius: 6,
                  fontSize: "0.85rem",
                  fontFamily: "monospace",
                }}
                required
              />
            </div>

            <div>
              <label style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--color-text-muted)", display: "block", marginBottom: 6 }}>
                Subscribed Security Events:
              </label>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={subEvents["finding.critical"]}
                    onChange={(e) => setSubEvents({ ...subEvents, "finding.critical": e.target.checked })}
                  />
                  Critical DAST Findings
                </label>
                <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={subEvents["finding.high"]}
                    onChange={(e) => setSubEvents({ ...subEvents, "finding.high": e.target.checked })}
                  />
                  High DAST Findings
                </label>
                <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={subEvents["alert.critical"]}
                    onChange={(e) => setSubEvents({ ...subEvents, "alert.critical": e.target.checked })}
                  />
                  Critical SIEM Alerts
                </label>
                <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 6 }}>
                  <input
                    type="checkbox"
                    checked={subEvents["scan.completed"]}
                    onChange={(e) => setSubEvents({ ...subEvents, "scan.completed": e.target.checked })}
                  />
                  Scan Completions
                </label>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 6 }}>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setShowAddForm(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                tone="primary"
                size="sm"
                disabled={saving}
              >
                {saving ? "Saving..." : "Save Webhook"}
              </Button>
            </div>
          </form>
        )}

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 18 }}>
          <Button onClick={onClose}>Close</Button>
        </div>
      </div>
    </div>
  );
}

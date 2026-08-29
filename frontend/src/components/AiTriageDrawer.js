import React, { useState } from "react";
import Badge from "./ui/Badge";
import Button from "./ui/Button";

export default function AiTriageDrawer({ isOpen, onClose, data, type = "alert" }) {
  const [activeTab, setActiveTab] = useState("summary");
  const [copiedKey, setCopiedKey] = useState(null);

  if (!isOpen || !data) return null;

  const copySnippet = (key, text) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const isAlert = type === "alert";
  const remediationCode = isAlert ? (data.remediation_code || {}) : (data.edge_waf_mitigation || {});

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        right: 0,
        bottom: 0,
        left: 0,
        zIndex: 9999,
        background: "rgba(3, 10, 18, 0.75)",
        backdropFilter: "blur(4px)",
        display: "flex",
        justifyContent: "flex-end",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 640,
          height: "100%",
          background: "#0d1b2a",
          borderLeft: "1px solid rgba(86, 198, 255, 0.3)",
          boxShadow: "-8px 0 32px rgba(0, 0, 0, 0.6)",
          display: "flex",
          flexDirection: "column",
          overflowY: "auto",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: "20px 24px",
            borderBottom: "1px solid rgba(86, 198, 255, 0.15)",
            background: "linear-gradient(180deg, #112538 0%, #0d1b2a 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
              <span style={{ fontSize: "1.2rem" }}>🤖</span>
              <h2 style={{ margin: 0, fontSize: "1.15rem", color: "#fff", fontFamily: "var(--font-display)" }}>
                DecodeX AI Copilot
              </h2>
              <Badge tone="ok">Built-in SOC Engine</Badge>
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
              {isAlert ? "Automated Incident Triage & Response Playbook" : "Vulnerability Impact & Edge WAF Mitigation"}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--color-text-muted)",
              fontSize: "1.5rem",
              cursor: "pointer",
              padding: "4px 8px",
            }}
          >
            ×
          </button>
        </div>

        {/* Navigation Tabs */}
        <div
          style={{
            display: "flex",
            borderBottom: "1px solid rgba(86, 198, 255, 0.15)",
            background: "rgba(10, 25, 41, 0.6)",
          }}
        >
          <button
            onClick={() => setActiveTab("summary")}
            style={{
              flex: 1,
              padding: "12px 16px",
              background: activeTab === "summary" ? "rgba(86, 198, 255, 0.1)" : "transparent",
              color: activeTab === "summary" ? "#56c6ff" : "var(--color-text-muted)",
              border: "none",
              borderBottom: activeTab === "summary" ? "2px solid #56c6ff" : "2px solid transparent",
              cursor: "pointer",
              fontWeight: 600,
              fontSize: "0.85rem",
            }}
          >
            Investigation
          </button>
          <button
            onClick={() => setActiveTab("mitre")}
            style={{
              flex: 1,
              padding: "12px 16px",
              background: activeTab === "mitre" ? "rgba(86, 198, 255, 0.1)" : "transparent",
              color: activeTab === "mitre" ? "#56c6ff" : "var(--color-text-muted)",
              border: "none",
              borderBottom: activeTab === "mitre" ? "2px solid #56c6ff" : "2px solid transparent",
              cursor: "pointer",
              fontWeight: 600,
              fontSize: "0.85rem",
            }}
          >
            {isAlert ? "MITRE ATT&CK" : "Root Cause & Patch"}
          </button>
          <button
            onClick={() => setActiveTab("remediation")}
            style={{
              flex: 1,
              padding: "12px 16px",
              background: activeTab === "remediation" ? "rgba(86, 198, 255, 0.1)" : "transparent",
              color: activeTab === "remediation" ? "#56c6ff" : "var(--color-text-muted)",
              border: "none",
              borderBottom: activeTab === "remediation" ? "2px solid #56c6ff" : "2px solid transparent",
              cursor: "pointer",
              fontWeight: 600,
              fontSize: "0.85rem",
            }}
          >
            Edge WAF & Scripts
          </button>
        </div>

        {/* Content Body */}
        <div style={{ padding: 24, flex: 1, display: "flex", flexDirection: "column", gap: 20 }}>
          {/* Severity & Score Banner */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "14px 18px",
              borderRadius: 8,
              background: "rgba(14, 42, 66, 0.8)",
              border: "1px solid rgba(86, 198, 255, 0.2)",
            }}
          >
            <div>
              <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", textTransform: "uppercase" }}>
                Assessed Severity
              </div>
              <div style={{ fontSize: "1.1rem", fontWeight: "bold", color: "#fff", marginTop: 2 }}>
                <Badge tone={data.severity === "CRITICAL" || data.severity === "HIGH" ? "danger" : "warn"}>
                  {data.severity}
                </Badge>
              </div>
            </div>
            {data.risk_score ? (
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>Risk Score</div>
                <div style={{ fontSize: "1.2rem", fontWeight: "bold", color: "#56c6ff" }}>
                  {data.risk_score} <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>/ 100</span>
                </div>
              </div>
            ) : null}
          </div>

          {/* TAB 1: SUMMARY */}
          {activeTab === "summary" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <h4 style={{ margin: "0 0 8px 0", color: "#56c6ff", fontSize: "0.95rem" }}>
                  Executive Incident Summary
                </h4>
                <div
                  style={{
                    lineHeight: 1.6,
                    fontSize: "0.9rem",
                    color: "rgba(255, 255, 255, 0.9)",
                    background: "rgba(255, 255, 255, 0.03)",
                    padding: 16,
                    borderRadius: 8,
                    border: "1px solid rgba(255, 255, 255, 0.08)",
                  }}
                  dangerouslySetInnerHTML={{ __html: data.executive_summary || "" }}
                />
              </div>

              {data.blast_radius && (
                <div>
                  <h4 style={{ margin: "0 0 8px 0", color: "#ffb74d", fontSize: "0.95rem" }}>
                    Blast Radius Assessment
                  </h4>
                  <div
                    style={{
                      lineHeight: 1.5,
                      fontSize: "0.88rem",
                      color: "rgba(255, 255, 255, 0.85)",
                      background: "rgba(255, 183, 77, 0.08)",
                      padding: 14,
                      borderRadius: 8,
                      border: "1px solid rgba(255, 183, 77, 0.2)",
                    }}
                  >
                    {data.blast_radius}
                  </div>
                </div>
              )}

              {data.action_checklist && (
                <div>
                  <h4 style={{ margin: "0 0 8px 0", color: "#4caf50", fontSize: "0.95rem" }}>
                    SOC Analyst Action Checklist
                  </h4>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {data.action_checklist.map((item, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: "10px 14px",
                          borderRadius: 6,
                          background: "rgba(76, 175, 80, 0.08)",
                          border: "1px solid rgba(76, 175, 80, 0.2)",
                          fontSize: "0.85rem",
                          color: "#e8f5e9",
                        }}
                      >
                        {item}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {data.exploitability && (
                <div>
                  <h4 style={{ margin: "0 0 8px 0", color: "#56c6ff", fontSize: "0.95rem" }}>
                    Exploitability Likelihood
                  </h4>
                  <div
                    style={{
                      padding: 14,
                      borderRadius: 8,
                      background: "rgba(86, 198, 255, 0.08)",
                      border: "1px solid rgba(86, 198, 255, 0.2)",
                      fontSize: "0.88rem",
                      color: "#fff",
                    }}
                  >
                    {data.exploitability}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: MITRE OR ROOT CAUSE */}
          {activeTab === "mitre" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {isAlert && data.mitre_analysis ? (
                <>
                  <div
                    style={{
                      padding: 16,
                      borderRadius: 8,
                      background: "rgba(10, 30, 50, 0.6)",
                      border: "1px solid rgba(86, 198, 255, 0.2)",
                    }}
                  >
                    <div style={{ fontSize: "0.75rem", color: "#56c6ff", textTransform: "uppercase", fontWeight: 700 }}>
                      MITRE ATT&CK Tactic
                    </div>
                    <div style={{ fontSize: "1.1rem", color: "#fff", fontWeight: 700, marginTop: 4 }}>
                      {data.mitre_analysis.tactic}
                    </div>
                    <div style={{ fontSize: "0.9rem", color: "var(--color-text-muted)", marginTop: 2 }}>
                      Technique: <code>{data.mitre_analysis.technique_id}</code> — {data.mitre_analysis.technique_name}
                    </div>
                  </div>

                  <div>
                    <h4 style={{ margin: "0 0 8px 0", color: "#56c6ff", fontSize: "0.95rem" }}>
                      Tactical Adversary Intent
                    </h4>
                    <p style={{ margin: 0, fontSize: "0.88rem", lineHeight: 1.6, color: "rgba(255,255,255,0.85)" }}>
                      {data.mitre_analysis.attacker_motive}
                    </p>
                  </div>

                  <div>
                    <h4 style={{ margin: "0 0 8px 0", color: "#4caf50", fontSize: "0.95rem" }}>
                      Immediate Containment Protocol
                    </h4>
                    <p style={{ margin: 0, fontSize: "0.88rem", lineHeight: 1.6, color: "rgba(255,255,255,0.85)" }}>
                      {data.containment_guidance}
                    </p>
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <h4 style={{ margin: "0 0 8px 0", color: "#56c6ff", fontSize: "0.95rem" }}>
                      Root Cause Analysis
                    </h4>
                    <div
                      style={{
                        padding: 14,
                        borderRadius: 8,
                        background: "rgba(255,255,255,0.03)",
                        border: "1px solid rgba(255,255,255,0.08)",
                        fontSize: "0.88rem",
                        color: "#fff",
                        lineHeight: 1.6,
                      }}
                    >
                      {data.root_cause}
                    </div>
                  </div>

                  <div>
                    <h4 style={{ margin: "0 0 8px 0", color: "#4caf50", fontSize: "0.95rem" }}>
                      Developer Fix Guidance
                    </h4>
                    <div
                      style={{
                        padding: 14,
                        borderRadius: 8,
                        background: "rgba(76, 175, 80, 0.08)",
                        border: "1px solid rgba(76, 175, 80, 0.2)",
                        fontSize: "0.88rem",
                        color: "#e8f5e9",
                        lineHeight: 1.6,
                      }}
                    >
                      {data.developer_patch}
                    </div>
                  </div>

                  {data.evidence_snippet && (
                    <div>
                      <h4 style={{ margin: "0 0 8px 0", color: "#ffb74d", fontSize: "0.95rem" }}>
                        Discovered Evidence
                      </h4>
                      <pre
                        style={{
                          margin: 0,
                          padding: 12,
                          borderRadius: 6,
                          background: "#060f18",
                          border: "1px solid rgba(255,255,255,0.1)",
                          fontSize: "0.8rem",
                          color: "#90caf9",
                          overflowX: "auto",
                        }}
                      >
                        {data.evidence_snippet}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {/* TAB 3: REMEDIATION CODE & PLAYBOOKS */}
          {activeTab === "remediation" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
                Ready-to-deploy firewall rules, middleware filters, and containment commands generated for this specific incident:
              </div>

              {Object.entries(remediationCode).map(([platform, code]) => (
                <div
                  key={platform}
                  style={{
                    borderRadius: 8,
                    overflow: "hidden",
                    border: "1px solid rgba(86, 198, 255, 0.2)",
                    background: "#081420",
                  }}
                >
                  <div
                    style={{
                      padding: "10px 16px",
                      background: "rgba(86, 198, 255, 0.1)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <span style={{ fontSize: "0.82rem", fontWeight: 700, color: "#56c6ff", textTransform: "uppercase" }}>
                      {platform.replace("_", " ")}
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => copySnippet(platform, code)}
                      style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                    >
                      {copiedKey === platform ? "✓ Copied!" : "Copy Code"}
                    </Button>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      padding: 14,
                      fontSize: "0.8rem",
                      color: "#c8e6c9",
                      background: "#050c14",
                      overflowX: "auto",
                      fontFamily: "monospace",
                      lineHeight: 1.5,
                    }}
                  >
                    {code}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: "16px 24px",
            borderTop: "1px solid rgba(86, 198, 255, 0.15)",
            background: "rgba(10, 25, 41, 0.8)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)" }}>
            DecodeX Autonomous SOC AI Assistant
          </div>
          <Button size="sm" variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

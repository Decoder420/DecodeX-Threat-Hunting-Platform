import React, { useEffect, useState } from "react";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";

const INSTALL_HINTS = {
  nuclei: "ProjectDiscovery Nuclei for CVE vulnerability and configuration templating.",
  nmap: "Network port and service fingerprinter for perimeter surface mapping.",
  zap: "OWASP Zed Attack Proxy v2.17.0 for active spidering and passive vulnerability analysis.",
  httpx: "High-concurrency HTTP probing and technology identification.",
  builtin: "Core TLS verification, security headers, cookies, and sensitive file checks.",
};

export default function WebScannerHealthPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await webApi.getScannerStatus();
      setData(res.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load scanner status.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="websec__stack">
      <div className="surface websec__panel">
        <div className="websec__row">
          <div>
            <h2 style={{ margin: 0 }}>Scanner Engine Diagnostic Health</h2>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Real-time operational readiness across automated DAST testing engines and network scanners.
            </p>
          </div>
          <Button size="sm" onClick={load}>
            ↻ Refresh Health
          </Button>
        </div>

        {error ? <p className="error-text">{error}</p> : null}
        {loading ? <div className="muted">Running engine diagnostics…</div> : null}

        {data ? (
          <>
            <div
              style={{
                marginTop: 16,
                padding: "10px 14px",
                background: "rgba(255, 255, 255, 0.02)",
                borderRadius: 6,
                border: "1px solid var(--line, rgba(255, 255, 255, 0.08))",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: 8,
              }}
            >
              <div>
                <strong>Private / Lab Target Assessments:</strong>{" "}
                <span className="muted">
                  {data.allow_private_targets
                    ? "Permitted (Internal RFC1918 addresses can be assessed)"
                    : "Strict Cloud-Only (Private/loopback IPs blocked by SSRF firewall)"}
                </span>
              </div>
              <Badge tone={data.allow_private_targets ? "warn" : "ok"}>
                {data.allow_private_targets ? "LAB_PERMITTED" : "STRICT_RESTRICTED"}
              </Badge>
            </div>

            {/* ENGINES TABLE */}
            <div className="websec__table-wrap" style={{ marginTop: 16 }}>
              <table className="websec__table">
                <thead>
                  <tr>
                    <th>Scanning Engine</th>
                    <th>Availability</th>
                    <th>Installed Version</th>
                    <th>Operational Status</th>
                    <th>Engine Role &amp; Guidance</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.engines || {}).map(([name, info]) => (
                    <tr key={name}>
                      <td>
                        <strong style={{ textTransform: "uppercase" }}>{name}</strong>
                      </td>
                      <td>
                        <Badge tone={info.installed ? "ok" : "warn"}>
                          {info.installed ? "INSTALLED" : "OPTIONAL"}
                        </Badge>
                      </td>
                      <td className="websec__mono">{info.version || "built-in"}</td>
                      <td>
                        <Badge tone={info.status === "READY" ? "ok" : "warn"}>
                          {info.status}
                        </Badge>
                      </td>
                      <td className="muted" style={{ fontSize: "0.85rem" }}>
                        {info.note || INSTALL_HINTS[name] || "Security testing component"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* SCAN PROFILES MATRIX */}
            <div style={{ marginTop: 24 }}>
              <h3>Scan Profiles Engine Matrix</h3>
              <p className="muted" style={{ fontSize: "0.85rem", marginBottom: 12 }}>
                Each scan profile orchestrates specific engines and discovery depths to match assessment scope:
              </p>

              <div className="websec__table-wrap">
                <table className="websec__table">
                  <thead>
                    <tr>
                      <th>Profile</th>
                      <th>Built-in HTTP</th>
                      <th>OWASP ZAP</th>
                      <th>Nuclei</th>
                      <th>Nmap Ports</th>
                      <th>Max Depth</th>
                      <th>Timeout / Budget</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(data.profiles || {}).map(([pName, pConfig]) => (
                      <tr key={pName}>
                        <td>
                          <strong>{pName}</strong>
                        </td>
                        <td>
                          <Badge tone="ok">ENABLED</Badge>
                        </td>
                        <td>
                          <Badge tone={pConfig.zap ? "ok" : "muted"}>
                            {pConfig.zap ? "ACTIVE" : "SKIPPED"}
                          </Badge>
                        </td>
                        <td>
                          <Badge tone={pConfig.nuclei ? "ok" : "muted"}>
                            {pConfig.nuclei ? "ACTIVE" : "SKIPPED"}
                          </Badge>
                        </td>
                        <td>
                          <Badge tone={pConfig.nmap ? "ok" : "muted"}>
                            {pConfig.nmap ? "ACTIVE" : "SKIPPED"}
                          </Badge>
                        </td>
                        <td>
                          <code>{pConfig.max_depth ?? "1"} levels</code>
                        </td>
                        <td>
                          <code>{pConfig.budget_seconds ? `${pConfig.budget_seconds}s` : "Dynamic"}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
}

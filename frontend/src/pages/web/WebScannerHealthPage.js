import React, { useEffect, useState } from "react";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";

const INSTALL_HINTS = {
  nuclei: "Install Nuclei and ensure it is on PATH, or set NUCLEI_PATH.",
  nmap: "Install Nmap and ensure it is on PATH, or set NMAP_PATH.",
  zap: "Start OWASP ZAP in daemon mode and set ZAP_ENABLED=true, ZAP_URL, ZAP_API_KEY.",
  httpx: "Built-in HTTP discovery is used; external httpx is optional.",
  builtin: "Always available — TLS, headers, cookies, common files, tech fingerprinting.",
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
          <h2>Scanner health</h2>
          <Button size="sm" onClick={load}>
            Refresh
          </Button>
        </div>
        <p className="muted">
          Missing engines do not crash scans — they are skipped with a warning.
          Private/lab targets require WEBSCAN_ALLOW_PRIVATE_TARGETS=true.
        </p>
        {error ? <p className="error-text">{error}</p> : null}
        {loading ? <div className="muted">Loading…</div> : null}
        {data ? (
          <>
            <p>
              Lab private targets allowed:{" "}
              <Badge tone={data.allow_private_targets ? "warn" : "ok"}>
                {String(data.allow_private_targets)}
              </Badge>
            </p>
            <div className="websec__table-wrap">
              <table className="websec__table">
                <thead>
                  <tr>
                    <th>Engine</th>
                    <th>Installed</th>
                    <th>Version</th>
                    <th>Status</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.engines || {}).map(([name, info]) => (
                    <tr key={name}>
                      <td>
                        <strong>{name}</strong>
                      </td>
                      <td>{info.installed ? "Yes" : "No"}</td>
                      <td className="websec__mono">{info.version || "—"}</td>
                      <td>
                        <Badge tone={info.status === "READY" ? "ok" : "warn"}>
                          {info.status}
                        </Badge>
                      </td>
                      <td className="muted">
                        {info.note || INSTALL_HINTS[name] || ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h3>Profiles</h3>
            <pre className="websec__pre">
              {JSON.stringify(data.profiles || {}, null, 2)}
            </pre>
          </>
        ) : null}
      </div>
    </div>
  );
}

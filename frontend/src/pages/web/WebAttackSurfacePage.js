import React, { useEffect, useState } from "react";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";

export default function WebAttackSurfacePage() {
  const [surfaces, setSurfaces] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await webApi.getAttackSurface();
      setSurfaces(res.data.surfaces || []);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load attack surface.");
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
          <h2>Attack surface</h2>
          <Button size="sm" onClick={load}>
            Refresh
          </Button>
        </div>
        <p className="muted">
          Hosts, ports, technologies, and discovered URLs from the latest completed scans.
        </p>
        {error ? <p className="error-text">{error}</p> : null}
        {loading ? <div className="muted">Loading…</div> : null}
        {!loading && !surfaces.length ? (
          <div className="muted">No completed scans yet.</div>
        ) : null}

        {surfaces.map((node) => (
          <div key={node.scan_id} className="websec__tree">
            <div className="websec__tree-host">
              <strong>{node.target?.name || `Target #${node.target?.id}`}</strong>
              <span className="websec__mono">{node.target?.url}</span>
              <Badge>risk {node.risk_score}</Badge>
            </div>
            <ul className="websec__tree-list">
              {(node.ports || []).length ? (
                (node.ports || []).map((p, idx) => (
                  <li key={`${p.port}-${idx}`}>
                    {p.port}/{p.protocol || "tcp"} — {p.state || "open"}{" "}
                    {p.service || p.product || ""}
                  </li>
                ))
              ) : (
                <li className="muted">No port data (Nmap skipped or unavailable)</li>
              )}
              {(node.technologies || []).map((tech, idx) => (
                <li key={`t-${idx}`}>
                  Tech: {tech.name || tech.technology}
                  {tech.version ? ` ${tech.version}` : ""}{" "}
                  <span className="muted">
                    ({tech.confidence != null ? `${tech.confidence}%` : "n/a"})
                  </span>
                </li>
              ))}
              {(node.urls || []).slice(0, 15).map((u) => (
                <li key={u} className="websec__mono">
                  {u}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";

export default function WebAttackSurfacePage() {
  const [surfaces, setSurfaces] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

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

  const filteredSurfaces = useMemo(() => {
    if (!search) return surfaces;
    const term = search.toLowerCase();
    return surfaces.filter((s) => {
      const name = (s.target?.name || "").toLowerCase();
      const url = (s.target?.url || "").toLowerCase();
      const matchUrl = (s.urls || []).some((u) => u.toLowerCase().includes(term));
      const matchTech = (s.technologies || []).some((t) =>
        (t.name || t.technology || "").toLowerCase().includes(term)
      );
      const matchPort = (s.ports || []).some((p) => String(p.port).includes(term));
      return name.includes(term) || url.includes(term) || matchUrl || matchTech || matchPort;
    });
  }, [surfaces, search]);

  const metrics = useMemo(() => {
    const totalTargets = surfaces.length;
    const totalUrls = surfaces.reduce((acc, s) => acc + (s.urls || []).length, 0);
    const totalPorts = surfaces.reduce((acc, s) => acc + (s.ports || []).length, 0);
    return { totalTargets, totalUrls, totalPorts };
  }, [surfaces]);

  return (
    <div className="websec__stack">
      <div className="surface websec__panel">
        <div className="websec__row">
          <div>
            <h2 style={{ margin: 0 }}>Attack Surface Explorer</h2>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Consolidated asset inventory of discovered web routes, open ports, and fingerprinted technologies from completed security scans.
            </p>
          </div>
          <Button size="sm" onClick={load}>
            ↻ Refresh
          </Button>
        </div>

        {/* METRICS TILES */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            gap: 12,
            marginTop: 16,
            marginBottom: 16,
          }}
        >
          <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.02)", borderRadius: 6, border: "1px solid var(--line, #222)" }}>
            <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Targets Assessed</div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700 }}>{metrics.totalTargets}</div>
          </div>
          <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.02)", borderRadius: 6, border: "1px solid var(--line, #222)" }}>
            <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Discovered Endpoints</div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "var(--accent, #3ee0a2)" }}>{metrics.totalUrls}</div>
          </div>
          <div style={{ padding: "10px 14px", background: "rgba(255, 255, 255, 0.02)", borderRadius: 6, border: "1px solid var(--line, #222)" }}>
            <div className="muted" style={{ fontSize: "0.75rem", textTransform: "uppercase" }}>Discovered Service Ports</div>
            <div style={{ fontSize: "1.4rem", fontWeight: 700, color: "var(--info, #5ec8ff)" }}>{metrics.totalPorts}</div>
          </div>
        </div>

        {/* SEARCH BAR */}
        <input
          className="field__input"
          style={{ width: "100%", marginBottom: 16 }}
          placeholder="Filter attack surface by target name, URL, endpoint path, technology, or port..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        {error ? <p className="error-text">{error}</p> : null}
        {loading ? <div className="muted">Loading attack surface telemetry…</div> : null}
        {!loading && !filteredSurfaces.length ? (
          <div className="muted">No matching attack surface records found.</div>
        ) : null}

        {/* TARGET ATTACK SURFACE CARDS */}
        {filteredSurfaces.map((node) => (
          <div
            key={node.scan_id}
            className="surface"
            style={{
              padding: 16,
              marginBottom: 16,
              border: "1px solid var(--line, rgba(255, 255, 255, 0.1))",
              borderRadius: 8,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12, marginBottom: 12 }}>
              <div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <h3 style={{ margin: 0 }}>
                    {node.target?.name || `Target #${node.target?.id}`}
                  </h3>
                  <Badge tone={node.risk_score >= 70 ? "danger" : node.risk_score >= 40 ? "warn" : "ok"}>
                    Risk {node.risk_score}/100
                  </Badge>
                </div>
                <div className="websec__mono" style={{ fontSize: "0.85rem", color: "var(--accent, #3ee0a2)", marginTop: 2 }}>
                  {node.target?.url}
                </div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <Link to={`/webscan/map?scan=${node.scan_id}`}>
                  <Button size="sm" variant="primary">
                    🗺️ Explore Website Map
                  </Button>
                </Link>
                <Link to={`/webscan/findings?scan=${node.scan_id}`}>
                  <Button size="sm">
                    View Findings
                  </Button>
                </Link>
              </div>
            </div>

            {/* OPEN PORTS SECTION */}
            <div style={{ marginBottom: 12 }}>
              <span className="muted" style={{ fontSize: "0.8rem", textTransform: "uppercase", fontWeight: 600 }}>
                Discovered Service Ports:
              </span>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                {(node.ports || []).length ? (
                  node.ports.map((p, idx) => (
                    <span
                      key={`${p.port}-${idx}`}
                      style={{
                        padding: "3px 8px",
                        background: "rgba(94, 200, 255, 0.1)",
                        border: "1px solid rgba(94, 200, 255, 0.3)",
                        borderRadius: 4,
                        fontSize: "0.78rem",
                        fontFamily: "monospace",
                      }}
                    >
                      {p.port}/{p.protocol || "tcp"} {p.service ? `(${p.service})` : ""}
                    </span>
                  ))
                ) : (
                  <span className="muted" style={{ fontSize: "0.8rem" }}>Standard Web (80/443)</span>
                )}
              </div>
            </div>

            {/* DETECTED TECHNOLOGIES */}
            <div style={{ marginBottom: 12 }}>
              <span className="muted" style={{ fontSize: "0.8rem", textTransform: "uppercase", fontWeight: 600 }}>
                Fingerprinted Web Technologies:
              </span>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                {(node.technologies || []).length ? (
                  node.technologies.map((t, idx) => (
                    <span
                      key={`tech-${idx}`}
                      style={{
                        padding: "3px 8px",
                        background: "rgba(62, 224, 162, 0.08)",
                        border: "1px solid rgba(62, 224, 162, 0.25)",
                        borderRadius: 4,
                        fontSize: "0.78rem",
                      }}
                    >
                      <strong>{t.name || t.technology}</strong>
                      {t.version ? ` v${t.version}` : ""}
                      {t.confidence != null ? ` (${t.confidence}%)` : ""}
                    </span>
                  ))
                ) : (
                  <span className="muted" style={{ fontSize: "0.8rem" }}>Standard Web Stack</span>
                )}
              </div>
            </div>

            {/* ENDPOINTS LIST */}
            <div>
              <span className="muted" style={{ fontSize: "0.8rem", textTransform: "uppercase", fontWeight: 600 }}>
                Discovered Endpoints Sample ({(node.urls || []).length} total):
              </span>
              <div
                style={{
                  marginTop: 6,
                  maxHeight: 180,
                  overflowY: "auto",
                  background: "#03070d",
                  padding: "8px 12px",
                  borderRadius: 6,
                  border: "1px solid var(--line, #222)",
                }}
              >
                {(node.urls || []).length ? (
                  (node.urls || []).map((u, idx) => (
                    <div
                      key={`${u}-${idx}`}
                      style={{
                        fontSize: "0.8rem",
                        fontFamily: "monospace",
                        color: "var(--text-muted, #8fa3a0)",
                        padding: "2px 0",
                        borderBottom: "1px solid rgba(255,255,255,0.03)",
                      }}
                    >
                      {u}
                    </div>
                  ))
                ) : (
                  <div className="muted" style={{ fontSize: "0.8rem" }}>No crawled endpoints recorded.</div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

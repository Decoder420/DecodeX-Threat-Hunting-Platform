import React, { useState, useEffect } from "react";
import Button from "./ui/Button";
import Badge from "./ui/Badge";
import { getMitreMatrix } from "../api";

export default function MitreAttackMatrix({ onSelectTechniqueForStudio }) {
  const [matrixData, setMatrixData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  useEffect(() => {
    loadMatrix();
  }, []);

  const loadMatrix = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await getMitreMatrix();
      setMatrixData(res.data);
    } catch (err) {
      setError("Failed to load MITRE ATT&CK coverage matrix.");
    } finally {
      setLoading(false);
    }
  };

  const summary = matrixData?.summary || {
    total_tactics: 12,
    covered_tactics: 0,
    total_techniques: 0,
    covered_techniques: 0,
    coverage_percentage: 0,
    active_rules_count: 0,
  };

  const filteredTactics = (matrixData?.tactics || []).map((tactic) => {
    if (!searchQuery.trim()) return tactic;
    const q = searchQuery.toLowerCase();
    const matchesTactic = tactic.tactic_name.toLowerCase().includes(q);
    const filteredTechs = tactic.techniques.filter(
      (tech) =>
        tech.id.toLowerCase().includes(q) ||
        tech.name.toLowerCase().includes(q) ||
        (tech.rules || []).some((r) => r.description?.toLowerCase().includes(q))
    );
    return {
      ...tactic,
      techniques: matchesTactic ? tactic.techniques : filteredTechs,
    };
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Top Header & Summary KPI Strip */}
      <div
        style={{
          background: "var(--bg-2)",
          border: "1px solid var(--line)",
          borderRadius: 12,
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: 16,
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 16,
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontSize: "1.4rem" }}>🎯</span>
              <h2 style={{ margin: 0, fontSize: "1.2rem", fontWeight: 700 }}>
                MITRE ATT&amp;CK Enterprise Coverage Matrix
              </h2>
              <Badge tone="primary">Enterprise v14</Badge>
            </div>
            <p
              style={{
                margin: "4px 0 0",
                fontSize: "0.85rem",
                color: "var(--color-text-muted)",
              }}
            >
              Real-time threat detection coverage mapped against adversary tactics and techniques.
            </p>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <input
              type="text"
              placeholder="Search technique or ID (e.g. T1059, PowerShell)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: "var(--bg-1)",
                border: "1px solid var(--line)",
                color: "var(--text)",
                padding: "8px 14px",
                borderRadius: 8,
                fontSize: "0.85rem",
                width: 280,
              }}
            />
            <Button size="sm" variant="secondary" onClick={loadMatrix}>
              🔄 Refresh
            </Button>
          </div>
        </div>

        {/* KPI Metrics */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
            gap: 12,
            marginTop: 4,
          }}
        >
          <div
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              padding: "12px 16px",
              borderRadius: 8,
            }}
          >
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              Tactics Coverage
            </div>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "var(--text)", marginTop: 4 }}>
              {summary.covered_tactics} / {summary.total_tactics}
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: 2 }}>
              {Math.round((summary.covered_tactics / (summary.total_tactics || 1)) * 100)}% Tactics with active rules
            </div>
          </div>

          <div
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              padding: "12px 16px",
              borderRadius: 8,
            }}
          >
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              Technique Coverage
            </div>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "#3ee0a2", marginTop: 4 }}>
              {summary.covered_techniques} / {summary.total_techniques}
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: 2 }}>
              {summary.coverage_percentage}% technique coverage
            </div>
          </div>

          <div
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              padding: "12px 16px",
              borderRadius: 8,
            }}
          >
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              Active Detection Rules
            </div>
            <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "#56c6ff", marginTop: 4 }}>
              {summary.active_rules_count}
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: 2 }}>
              Compiled Sigma &amp; native rules
            </div>
          </div>

          <div
            style={{
              background: "var(--bg-1)",
              border: "1px solid var(--line)",
              padding: "12px 16px",
              borderRadius: 8,
            }}
          >
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
              Coverage Progress
            </div>
            <div style={{ marginTop: 8 }}>
              <div style={{ width: "100%", height: 8, background: "var(--line)", borderRadius: 4, overflow: "hidden" }}>
                <div
                  style={{
                    width: `${summary.coverage_percentage}%`,
                    height: "100%",
                    background: "linear-gradient(90deg, #3ee0a2, #56c6ff)",
                    borderRadius: 4,
                  }}
                />
              </div>
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--color-text-muted)", marginTop: 6 }}>
              Target: 80%+ enterprise coverage
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div style={{ padding: "14px 18px", background: "rgba(255, 92, 122, 0.1)", color: "#ff5c7a", borderRadius: 8 }}>
          {error}
        </div>
      )}

      {loading ? (
        <div style={{ padding: "40px", textAlign: "center", color: "var(--color-text-muted)" }}>
          Loading MITRE ATT&amp;CK matrix...
        </div>
      ) : (
        /* Matrix Grid Container */
        <div
          style={{
            display: "grid",
            gridAutoFlow: "column",
            gridAutoColumns: "minmax(220px, 1fr)",
            gap: 12,
            overflowX: "auto",
            paddingBottom: 16,
          }}
        >
          {filteredTactics.map((tactic) => (
            <div
              key={tactic.tactic_id}
              style={{
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                borderRadius: 10,
                display: "flex",
                flexDirection: "column",
                overflow: "hidden",
                minWidth: 220,
              }}
            >
              {/* Tactic Header */}
              <div
                style={{
                  padding: "10px 12px",
                  background: tactic.covered
                    ? "rgba(62, 224, 162, 0.08)"
                    : "rgba(0, 0, 0, 0.2)",
                  borderBottom: "1px solid var(--line)",
                  display: "flex",
                  flexDirection: "column",
                  gap: 2,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "0.68rem", fontWeight: 700, color: "var(--color-text-muted)" }}>
                    {tactic.tactic_id}
                  </span>
                  {tactic.covered ? (
                    <Badge tone="ok">Covered</Badge>
                  ) : (
                    <span style={{ fontSize: "0.68rem", color: "var(--color-text-muted)" }}>0 rules</span>
                  )}
                </div>
                <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text)" }}>
                  {tactic.tactic_name}
                </div>
              </div>

              {/* Techniques List */}
              <div style={{ padding: "8px", display: "flex", flexDirection: "column", gap: 6, flexGrow: 1 }}>
                {tactic.techniques.map((tech) => (
                  <div
                    key={tech.id}
                    onClick={() => setSelectedTechnique({ ...tech, tactic_name: tactic.tactic_name })}
                    style={{
                      padding: "8px 10px",
                      borderRadius: 6,
                      background: tech.covered
                        ? "rgba(62, 224, 162, 0.08)"
                        : "var(--bg-1)",
                      border: tech.covered
                        ? "1px solid rgba(62, 224, 162, 0.35)"
                        : "1px solid var(--line)",
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 2 }}>
                      <span style={{ fontSize: "0.72rem", fontWeight: 700, color: tech.covered ? "#3ee0a2" : "var(--color-text-muted)" }}>
                        {tech.id}
                      </span>
                      {tech.covered ? (
                        <span
                          style={{
                            fontSize: "0.65rem",
                            background: "#3ee0a2",
                            color: "#000",
                            fontWeight: 800,
                            padding: "1px 5px",
                            borderRadius: 4,
                          }}
                        >
                          {tech.rule_count} {tech.rule_count === 1 ? "rule" : "rules"}
                        </span>
                      ) : (
                        <span style={{ fontSize: "0.65rem", color: "var(--color-text-muted)" }}>
                          Gap
                        </span>
                      )}
                    </div>
                    <div
                      style={{
                        fontSize: "0.78rem",
                        color: tech.covered ? "var(--text)" : "var(--color-text-muted)",
                        fontWeight: tech.covered ? 600 : 400,
                        lineHeight: 1.25,
                      }}
                    >
                      {tech.name}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Selected Technique Drawer / Modal */}
      {selectedTechnique && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0,0,0,0.7)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            zIndex: 1000,
            padding: 20,
          }}
          onClick={() => setSelectedTechnique(null)}
        >
          <div
            style={{
              background: "var(--bg-2)",
              border: "1px solid var(--line)",
              borderRadius: 12,
              maxWidth: 540,
              width: "100%",
              padding: "24px",
              boxShadow: "0 12px 36px rgba(0,0,0,0.5)",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Badge tone={selectedTechnique.covered ? "ok" : "warn"}>
                    {selectedTechnique.id}
                  </Badge>
                  <span style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
                    {selectedTechnique.tactic_name}
                  </span>
                </div>
                <h3 style={{ margin: "8px 0 0", fontSize: "1.1rem", fontWeight: 700 }}>
                  {selectedTechnique.name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
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

            <div style={{ margin: "16px 0", fontSize: "0.85rem", color: "var(--color-text-muted)" }}>
              {selectedTechnique.covered ? (
                <div>
                  <div style={{ fontWeight: 600, color: "var(--text)", marginBottom: 8 }}>
                    Active Detection Rules ({selectedTechnique.rules?.length || 0}):
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {(selectedTechnique.rules || []).map((r, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: "10px 12px",
                          background: "var(--bg-1)",
                          border: "1px solid var(--line)",
                          borderRadius: 8,
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                          <strong>{r.id}</strong>
                          <Badge tone="danger">{r.severity?.toUpperCase()}</Badge>
                        </div>
                        <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
                          {r.description}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ padding: "16px", background: "rgba(255, 170, 0, 0.08)", border: "1px solid rgba(255, 170, 0, 0.25)", borderRadius: 8 }}>
                  <div style={{ fontWeight: 700, color: "#ffa500", marginBottom: 4 }}>
                    ⚠️ Detection Gap Identified
                  </div>
                  <div>
                    No active Sigma or native detection rules currently cover technique{" "}
                    <strong>{selectedTechnique.id}</strong> ({selectedTechnique.name}).
                  </div>
                </div>
              )}
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 20 }}>
              <Button variant="secondary" onClick={() => setSelectedTechnique(null)}>
                Close
              </Button>
              {onSelectTechniqueForStudio && (
                <Button
                  tone="primary"
                  onClick={() => {
                    onSelectTechniqueForStudio(selectedTechnique);
                    setSelectedTechnique(null);
                  }}
                >
                  ⚡ Author / Test Rule in Studio
                </Button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

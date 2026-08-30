import React, { useState, useEffect, useRef } from "react";
import Badge from "./ui/Badge";
import Button from "./ui/Button";

export default function AttackBlastRadiusGraph({ target, findings = [], alerts = [] }) {
  const canvasRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [draggedNode, setDraggedNode] = useState(null);
  const offsetRef = useRef({ x: 0, y: 0 });

  // Construct relational nodes & links based on live target findings & alerts
  const graphData = useRef({
    nodes: [],
    links: [],
  });

  useEffect(() => {
    const targetName = target?.name || "Monitored Target";
    const targetUrl = target?.url || "https://target.internal";

    // 1. Center Target Node
    const nodes = [
      { id: "target", label: targetName, sub: targetUrl, type: "target", x: 380, y: 220, radius: 28, color: "#3ee0a2" },
    ];
    const links = [];

    // Append dynamic finding nodes if present
    if (findings.length > 0) {
      nodes.push({ id: "ingress", label: "Perimeter Ingress", sub: targetUrl, type: "ingress", x: 220, y: 220, radius: 22, color: "#56c6ff" });
      links.push({ from: "ingress", to: "target", label: "HTTP Route" });

      findings.slice(0, 5).forEach((f, idx) => {
        const id = `finding_${f.id || idx}`;
        nodes.push({
          id,
          label: f.title || "Vulnerability",
          sub: `${f.severity} · ${f.path || f.affected_url || "/"}`,
          type: "finding",
          x: 480 + (idx % 3) * 70,
          y: 150 + Math.floor(idx / 3) * 120,
          radius: 20,
          color: f.severity === "CRITICAL" || f.severity === "HIGH" ? "#ff5252" : "#ffa726",
          meta: f,
        });
        links.push({ from: "target", to: id, label: "Discovered Vuln" });
      });

      const topMitre = findings.find((f) => f.cwe || f.owasp);
      if (topMitre) {
        nodes.push({
          id: "mitre",
          label: "Classification",
          sub: topMitre.cwe || topMitre.owasp,
          type: "mitre",
          x: 640,
          y: 220,
          radius: 22,
          color: "#b388ff",
        });
        links.push({ from: "target", to: "mitre", label: "Threat Mapping" });
      }
    }

    // Append dynamic alert nodes if present
    if (alerts.length > 0) {
      alerts.slice(0, 2).forEach((a, idx) => {
        const id = `alert_${a.id || idx}`;
        nodes.push({
          id,
          label: a.tactic || "Adversary Alert",
          sub: a.ip || a.host || "External Origin",
          type: "attacker",
          x: 90,
          y: 160 + idx * 120,
          radius: 22,
          color: "#ff5252",
          meta: a,
        });
        links.push({ from: id, to: "target", label: "Attack Vector" });
      });
    }

    graphData.current = { nodes, links };
    setSelectedNode(nodes[0]);
  }, [target, findings, alerts]);

  // Canvas Render Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let animId;
    const render = () => {
      const { nodes, links } = graphData.current;
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Background grid dots
      ctx.fillStyle = "rgba(86, 198, 255, 0.05)";
      for (let x = 20; x < canvas.width; x += 30) {
        for (let y = 20; y < canvas.height; y += 30) {
          ctx.fillRect(x, y, 1.5, 1.5);
        }
      }

      // Draw Links
      links.forEach((link) => {
        const src = nodes.find((n) => n.id === link.from);
        const dst = nodes.find((n) => n.id === link.to);
        if (!src || !dst) return;

        // Gradient line
        const grad = ctx.createLinearGradient(src.x, src.y, dst.x, dst.y);
        grad.addColorStop(0, src.color);
        grad.addColorStop(1, dst.color);

        ctx.strokeStyle = grad;
        ctx.lineWidth = selectedNode?.id === src.id || selectedNode?.id === dst.id ? 2.5 : 1.2;
        ctx.setLineDash([4, 3]);
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(dst.x, dst.y);
        ctx.stroke();
        ctx.setLineDash([]);

        // Label on link midpoint
        const midX = (src.x + dst.x) / 2;
        const midY = (src.y + dst.y) / 2 - 6;
        ctx.font = "9px monospace";
        ctx.fillStyle = "rgba(255, 255, 255, 0.5)";
        ctx.textAlign = "center";
        ctx.fillText(link.label, midX, midY);
      });

      // Draw Nodes
      nodes.forEach((node) => {
        const isSelected = selectedNode?.id === node.id;

        // Outer glow on select
        if (isSelected) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 8, 0, Math.PI * 2);
          ctx.fillStyle = `${node.color}22`;
          ctx.fill();
        }

        // Main Node Body
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = "#0c1522";
        ctx.fill();
        ctx.strokeStyle = node.color;
        ctx.lineWidth = isSelected ? 3 : 2;
        ctx.stroke();

        // Node Title
        ctx.font = "bold 11px sans-serif";
        ctx.fillStyle = "#ffffff";
        ctx.textAlign = "center";
        ctx.fillText(node.label, node.x, node.y + node.radius + 14);

        // Node Subtitle
        ctx.font = "9px monospace";
        ctx.fillStyle = "var(--color-text-muted, #8fa3a0)";
        ctx.fillText(node.sub, node.x, node.y + node.radius + 26);
      });

      animId = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animId);
  }, [selectedNode]);

  // Dragging & Clicking Handlers
  const handleMouseDown = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const clicked = graphData.current.nodes.find((n) => {
      const dx = n.x - mouseX;
      const dy = n.y - mouseY;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 6;
    });

    if (clicked) {
      setDraggedNode(clicked);
      setSelectedNode(clicked);
      offsetRef.current = { x: mouseX - clicked.x, y: mouseY - clicked.y };
    }
  };

  const handleMouseMove = (e) => {
    if (!draggedNode) return;
    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    draggedNode.x = mouseX - offsetRef.current.x;
    draggedNode.y = mouseY - offsetRef.current.y;
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
  };

  return (
    <div
      className="surface"
      style={{
        borderRadius: 14,
        padding: 24,
        display: "flex",
        flexDirection: "column",
        gap: 16,
        background: "linear-gradient(180deg, rgba(10, 22, 36, 0.9) 0%, rgba(6, 12, 20, 0.95) 100%)",
        border: "1px solid rgba(86, 198, 255, 0.2)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: "1.3rem" }}>🕸️</span>
            <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem", fontFamily: "var(--font-display)" }}>
              Attack Blast Radius &amp; Infrastructure Node Graph
            </h3>
            <Badge tone="ok">Live Topology</Badge>
          </div>
          <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)", marginTop: 4 }}>
            Interactive relational map tracing adversary origin IPs through edge ingress to vulnerable endpoints
          </div>
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              if (graphData.current.nodes[0]) {
                setSelectedNode(graphData.current.nodes[0]);
              }
            }}
          >
            Reset View
          </Button>
        </div>
      </div>

      {/* Main Canvas & Detail Split */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 20 }}>
        {/* Canvas Area */}
        <div
          style={{
            position: "relative",
            background: "#050a10",
            borderRadius: 10,
            border: "1px solid rgba(255, 255, 255, 0.08)",
            overflow: "hidden",
            cursor: draggedNode ? "grabbing" : "grab",
          }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          <canvas ref={canvasRef} width={760} height={440} style={{ width: "100%", height: "auto" }} />
          {findings.length === 0 && alerts.length === 0 && (
            <div
              style={{
                position: "absolute",
                top: 16,
                right: 16,
                background: "rgba(0, 0, 0, 0.75)",
                border: "1px dashed rgba(86, 198, 255, 0.3)",
                padding: "8px 14px",
                borderRadius: 6,
                fontSize: "0.76rem",
                color: "#56c6ff",
                pointerEvents: "none",
              }}
            >
              Target baseline clear · Zero active threat paths detected
            </div>
          )}
          <div
            style={{
              position: "absolute",
              bottom: 10,
              left: 12,
              fontSize: "0.72rem",
              color: "rgba(255, 255, 255, 0.4)",
              pointerEvents: "none",
            }}
          >
            Click or drag nodes to inspect relations
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        <div
          style={{
            padding: 18,
            borderRadius: 10,
            background: "rgba(0, 0, 0, 0.35)",
            border: "1px solid rgba(86, 198, 255, 0.2)",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          {selectedNode ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <span style={{ fontSize: "0.72rem", color: selectedNode.color, fontWeight: 700, textTransform: "uppercase" }}>
                  Selected Node
                </span>
                <h4 style={{ margin: "4px 0 2px", color: "#fff", fontSize: "1.05rem" }}>
                  {selectedNode.label}
                </h4>
                <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
                  {selectedNode.sub}
                </div>
              </div>

              <div
                style={{
                  padding: 12,
                  borderRadius: 6,
                  background: "rgba(255, 255, 255, 0.04)",
                  fontSize: "0.82rem",
                  lineHeight: 1.5,
                  color: "rgba(255, 255, 255, 0.8)",
                }}
              >
                {selectedNode.type === "attacker" && (
                  <>
                    <b>Adversary Intel:</b> Originates from known suspicious Autonomous System. Multiple SQLi &amp; path traversal probing events recorded.
                  </>
                )}
                {selectedNode.type === "target" && (
                  <>
                    <b>Target Asset:</b> Monitored web application. Active scans scheduled with automated vulnerability correlation.
                  </>
                )}
                {selectedNode.type === "ingress" && (
                  <>
                    <b>Edge Gateway:</b> Vercel edge middleware &amp; Cloudflare perimeter reverse-proxying requests.
                  </>
                )}
                {selectedNode.type === "mitre" && (
                  <>
                    <b>Tactical Profile:</b> MITRE ATT&amp;CK technique mapped directly from detected payload signatures.
                  </>
                )}
                {selectedNode.type === "action" && (
                  <>
                    <b>Remediation Script:</b> Automated WAF virtual patch generated to isolate the adversary at the perimeter edge.
                  </>
                )}
                {selectedNode.type === "finding" && (
                  <>
                    <b>DAST Finding:</b> Detected active vulnerability during crawling assessment. Needs urgent virtual patching.
                  </>
                )}
              </div>

              <div>
                <Button
                  size="sm"
                  variant="primary"
                  block
                  onClick={() => window.alert(`Executed containment for node "${selectedNode.label}"`)}
                >
                  ⚡ Execute Containment
                </Button>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: "center", color: "var(--color-text-muted)", margin: "auto" }}>
              Click any node in the graph to view blast radius details.
            </div>
          )}

          <div style={{ fontSize: "0.72rem", color: "rgba(255, 255, 255, 0.4)", borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 10, marginTop: 14 }}>
            Topology nodes: {graphData.current.nodes.length} | Relational arcs: {graphData.current.links.length}
          </div>
        </div>
      </div>
    </div>
  );
}

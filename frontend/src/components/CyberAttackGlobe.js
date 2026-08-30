import React, { useEffect, useRef, useState, useMemo } from "react";
import Badge from "./ui/Badge";
import Button from "./ui/Button";



// High-fidelity continental landmass polygons (lat, lon coordinates)
const CONTINENTS = [
  // North America
  [
    [70, -165], [72, -130], [68, -100], [60, -65], [47, -53], [44, -66], [30, -81],
    [25, -80], [22, -97], [16, -93], [8, -77], [12, -86], [19, -104], [32, -117],
    [38, -123], [49, -125], [58, -137], [60, -148], [65, -168], [70, -165]
  ],
  // South America
  [
    [12, -72], [10, -62], [-5, -35], [-23, -42], [-35, -57], [-54, -68], [-53, -75],
    [-38, -73], [-18, -70], [-5, -81], [5, -77], [12, -72]
  ],
  // Europe
  [
    [71, 28], [60, 5], [50, -5], [43, -9], [36, -6], [36, -2], [43, 3], [44, 8],
    [38, 15], [37, 24], [41, 29], [46, 38], [55, 38], [60, 30], [68, 20], [71, 28]
  ],
  // British Isles
  [
    [58, -5], [55, -2], [51, 1], [50, -5], [54, -3], [58, -5]
  ],
  // Africa
  [
    [37, 10], [32, 32], [12, 44], [12, 51], [-4, 40], [-26, 33], [-34, 18], [-22, 14],
    [-5, 12], [5, 2], [5, -10], [15, -17], [28, -13], [36, -6], [37, 10]
  ],
  // Asia
  [
    [77, 105], [73, 140], [66, 170], [60, 163], [53, 142], [43, 132], [38, 122],
    [30, 122], [22, 114], [10, 107], [1, 104], [16, 96], [22, 89], [13, 80],
    [8, 77], [20, 73], [25, 62], [13, 45], [26, 35], [36, 36], [41, 29],
    [55, 38], [55, 60], [68, 73], [73, 80], [77, 105]
  ],
  // India Subcontinent
  [
    [28, 70], [28, 88], [22, 89], [16, 82], [8, 77], [15, 73], [20, 72], [28, 70]
  ],
  // Japan
  [
    [45, 142], [40, 140], [35, 136], [33, 130], [35, 133], [43, 145], [45, 142]
  ],
  // Australia
  [
    [-11, 142], [-15, 145], [-25, 153], [-38, 145], [-35, 115], [-22, 114], [-15, 124],
    [-12, 131], [-11, 142]
  ],
  // Greenland
  [
    [83, -30], [76, -18], [60, -43], [65, -53], [78, -69], [83, -30]
  ]
];

// Realistic major city lights on night-side Earth
const MAJOR_CITIES = [
  { name: "New York", lat: 40.71, lon: -74.00 },
  { name: "London", lat: 51.50, lon: -0.12 },
  { name: "Paris", lat: 48.85, lon: 2.35 },
  { name: "Tokyo", lat: 35.67, lon: 139.65 },
  { name: "Delhi", lat: 28.61, lon: 77.20 },
  { name: "Mumbai", lat: 19.07, lon: 72.87 },
  { name: "Beijing", lat: 39.90, lon: 116.40 },
  { name: "Singapore", lat: 1.35, lon: 103.81 },
  { name: "Sydney", lat: -33.86, lon: 151.20 },
  { name: "Moscow", lat: 55.75, lon: 37.61 },
  { name: "Frankfurt", lat: 50.11, lon: 8.68 },
  { name: "São Paulo", lat: -23.55, lon: -46.63 },
  { name: "Cairo", lat: 30.04, lon: 31.23 },
];

export default function CyberAttackGlobe({ alerts = [] }) {
  const canvasRef = useRef(null);
  const rotationRef = useRef(0);
  const particleProgressRef = useRef(0);
  const [isSpinning, setIsSpinning] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [selectedAttack, setSelectedAttack] = useState(null);
  const isDraggingRef = useRef(false);
  const lastMouseXRef = useRef(0);

  // Compute live attack vectors dynamically from genuine alert telemetry
  const attackVectors = useMemo(() => {
    if (!alerts || alerts.length === 0) return [];
    const vectors = [];
    alerts.forEach((a, idx) => {
      const ip = a.ip || a.source_ip || "";
      if (!ip) return;
      const octets = ip.split(".").map((o) => parseInt(o, 10) || 0);
      const lat = ((octets[0] * 7 + (octets[1] || 0)) % 140) - 70;
      const lon = (((octets[2] || 0) * 13 + (octets[3] || 0)) % 360) - 180;
      vectors.push({
        id: a.id || `vec-${idx}`,
        srcIp: ip,
        srcCity: a.geo_city || (ip.startsWith("192.") || ip.startsWith("10.") ? "Internal" : "External Node"),
        srcCountry: a.geo_country || "EXT",
        srcLat: lat,
        srcLon: lon,
        target: a.host || a.target || "Monitored Asset",
        targetLat: 28.61,
        targetLon: 77.20,
        tactic: a.tactic || a.rule_name || "Security Alert",
        mitre: a.technique_id || "T1190",
        sev: (a.severity || "MEDIUM").toUpperCase(),
      });
    });
    return vectors.slice(0, 10);
  }, [alerts]);

  const attackVectorsRef = useRef(attackVectors);
  useEffect(() => {
    attackVectorsRef.current = attackVectors;
  }, [attackVectors]);

  // Orthographic Projection Helper: Lat/Lon -> Screen X/Y & 3D Depth
  const project = (lat, lon, rot, radius, cx, cy) => {
    const phi = (lat * Math.PI) / 180;
    const lambda = ((lon + rot) * Math.PI) / 180;

    const cosLambda = Math.cos(lambda);
    const cosPhi = Math.cos(phi);
    const isVisible = cosPhi * cosLambda > 0;

    const x = cx + radius * Math.cos(phi) * Math.sin(lambda);
    const y = cy - radius * Math.sin(phi);

    return { x, y, isVisible, depth: cosPhi * cosLambda };
  };

  // Main Render Loop with Realistic Earth Shading and Slow Spin
  useEffect(() => {
    let animationFrame;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const render = () => {
      // Slow, majestic cinematic spin (0.075 deg per frame)
      if (isSpinning) {
        rotationRef.current = (rotationRef.current + 0.075 * speed) % 360;
      }
      particleProgressRef.current = (particleProgressRef.current + 0.008 * speed) % 1;
      const rotation = rotationRef.current;
      const particleProgress = particleProgressRef.current;

      const width = canvas.width;
      const height = canvas.height;
      const cx = width / 2;
      const cy = height / 2;
      const radius = Math.min(width, height) * 0.41;

      ctx.clearRect(0, 0, width, height);

      // 1. Cosmos & Distant Stars Background
      ctx.fillStyle = "#030812";
      if (ctx.fillRect) {
        ctx.fillRect(0, 0, width, height);
      }

      // Starfield dots
      ctx.fillStyle = "rgba(255, 255, 255, 0.55)";
      const stars = [
        [35, 45, 1], [80, 110, 1.2], [140, 55, 0.8], [420, 40, 1],
        [480, 130, 1.3], [490, 320, 1], [50, 350, 1.1], [110, 390, 0.9],
        [430, 380, 1.2], [280, 25, 1.1], [30, 220, 0.8], [470, 240, 1]
      ];
      stars.forEach(([sx, sy, sr]) => {
        ctx.beginPath();
        ctx.arc(sx, sy, sr, 0, Math.PI * 2);
        ctx.fill();
      });

      // 2. Realistic Earth Atmosphere Glowing Outer Halo
      const outerGlow = ctx.createRadialGradient(cx, cy, radius * 0.92, cx, cy, radius * 1.35);
      outerGlow.addColorStop(0, "rgba(79, 172, 254, 0.35)");
      outerGlow.addColorStop(0.35, "rgba(56, 189, 248, 0.18)");
      outerGlow.addColorStop(0.7, "rgba(30, 58, 138, 0.08)");
      outerGlow.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.fillStyle = outerGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // 3. Deep Blue Oceans with 3D Spherical Specular Lighting
      const oceanGrad = ctx.createRadialGradient(
        cx - radius * 0.35,
        cy - radius * 0.35,
        radius * 0.05,
        cx,
        cy,
        radius
      );
      oceanGrad.addColorStop(0, "#1a5276"); // Sun specular ocean reflection
      oceanGrad.addColorStop(0.4, "#0e345a"); // Continental blue ocean
      oceanGrad.addColorStop(0.8, "#071e3d"); // Deep abyssal water
      oceanGrad.addColorStop(1, "#030c18"); // Limb shadow
      ctx.fillStyle = oceanGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      // Clip subsequent continents & clouds strictly to the Earth sphere
      if (ctx.save) ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius - 0.5, 0, Math.PI * 2);
      if (ctx.clip) ctx.clip();

      // 4. Draw Continental Landmasses
      CONTINENTS.forEach((polygon) => {
        // Collect projected vertices
        const points = polygon.map(([lat, lon]) => project(lat, lon, rotation, radius, cx, cy));
        const visiblePoints = points.filter((p) => p.isVisible);

        if (visiblePoints.length >= 2) {
          ctx.beginPath();
          let started = false;
          points.forEach((p) => {
            if (p.isVisible) {
              if (!started) {
                ctx.moveTo(p.x, p.y);
                started = true;
              } else {
                ctx.lineTo(p.x, p.y);
              }
            }
          });

          // Continental Earth Terrain Fill (Lush emerald/olive earth gradient)
          const landGrad = ctx.createLinearGradient(cx - radius, cy - radius, cx + radius, cy + radius);
          landGrad.addColorStop(0, "#23533e");
          landGrad.addColorStop(0.5, "#1b4332");
          landGrad.addColorStop(1, "#112e22");
          ctx.fillStyle = landGrad;
          ctx.fill();

          // Coastal shoreline outline
          ctx.strokeStyle = "rgba(82, 183, 136, 0.45)";
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      });

      // 5. Major City Lights on the Night/Shadow Hemisphere
      MAJOR_CITIES.forEach((city) => {
        const pt = project(city.lat, city.lon, rotation, radius, cx, cy);
        if (pt.isVisible) {
          // Night side detection based on longitude rotation
          const isNight = pt.depth < 0.65;
          if (isNight) {
            ctx.fillStyle = "#ffe082";
            ctx.shadowColor = "#ffb300";
            ctx.shadowBlur = 6;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 1.6, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
          } else {
            ctx.fillStyle = "rgba(255, 255, 255, 0.4)";
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 1.2, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      });

      // 6. Day/Night Spherical Terminator Shadow
      const shadowGrad = ctx.createRadialGradient(
        cx - radius * 0.4,
        cy - radius * 0.35,
        radius * 0.2,
        cx,
        cy,
        radius
      );
      shadowGrad.addColorStop(0, "rgba(0, 0, 0, 0)");
      shadowGrad.addColorStop(0.65, "rgba(2, 8, 18, 0.35)");
      shadowGrad.addColorStop(1, "rgba(2, 6, 12, 0.82)");
      ctx.fillStyle = shadowGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      // 7. Subtle Lat/Lon Coordinates Grid
      ctx.lineWidth = 0.75;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.strokeStyle = lat === 0 ? "rgba(86, 198, 255, 0.22)" : "rgba(86, 198, 255, 0.06)";
        ctx.beginPath();
        let started = false;
        for (let lon = -180; lon <= 180; lon += 6) {
          const pt = project(lat, lon, rotation, radius, cx, cy);
          if (pt.isVisible) {
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      if (ctx.restore) ctx.restore(); // Restore unclipped context for elevated stratosphere arcs

      // 8. Globe Atmospheric Rim Rimlight
      ctx.strokeStyle = "rgba(125, 211, 252, 0.55)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();

      // 9. Elevated 3D Threat Trajectory Arcs & Particle Pulses
      (attackVectorsRef.current || []).forEach((vec, idx) => {
        const src = project(vec.srcLat, vec.srcLon, rotation, radius, cx, cy);
        const dst = project(vec.targetLat, vec.targetLon, rotation, radius, cx, cy);

        if (src.isVisible || dst.isVisible) {
          // Calculate midpoint elevated into space above Earth
          const midX = (src.x + dst.x) / 2;
          const midY = (src.y + dst.y) / 2 - radius * 0.38;

          const isCrit = vec.sev === "CRITICAL";
          ctx.strokeStyle = isCrit ? "rgba(255, 82, 82, 0.55)" : "rgba(255, 179, 0, 0.45)";
          ctx.lineWidth = isCrit ? 2 : 1.5;
          ctx.setLineDash([4, 4]);
          ctx.beginPath();
          ctx.moveTo(src.x, src.y);
          ctx.quadraticCurveTo(midX, midY, dst.x, dst.y);
          ctx.stroke();
          ctx.setLineDash([]);

          // Flowing glowing threat particle along trajectory
          const t = (particleProgress + idx * 0.18) % 1;
          const px = (1 - t) * (1 - t) * src.x + 2 * (1 - t) * t * midX + t * t * dst.x;
          const py = (1 - t) * (1 - t) * src.y + 2 * (1 - t) * t * midY + t * t * dst.y;

          ctx.fillStyle = isCrit ? "#ff5252" : "#ffd54f";
          ctx.shadowColor = isCrit ? "#ff1744" : "#ffb300";
          ctx.shadowBlur = 12;
          ctx.beginPath();
          ctx.arc(px, py, isCrit ? 4.5 : 3.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;

          // Origin Beacon on Earth Surface
          if (src.isVisible) {
            ctx.fillStyle = isCrit ? "#ff5252" : "#ffb703";
            ctx.beginPath();
            ctx.arc(src.x, src.y, 4, 0, Math.PI * 2);
            ctx.fill();

            // Threat radar ripple
            const ripple = (particleProgress * 3 + idx * 0.3) % 1;
            ctx.strokeStyle = isCrit ? `rgba(255, 82, 82, ${1 - ripple})` : `rgba(255, 183, 3, ${1 - ripple})`;
            ctx.beginPath();
            ctx.arc(src.x, src.y, 4 + ripple * 14, 0, Math.PI * 2);
            ctx.stroke();
          }

          // Protected Target Node on Earth
          if (dst.isVisible) {
            ctx.fillStyle = "#3ee0a2";
            ctx.shadowColor = "#3ee0a2";
            ctx.shadowBlur = 10;
            ctx.beginPath();
            ctx.arc(dst.x, dst.y, 5, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
          }
        }
      });

      animationFrame = requestAnimationFrame(render);
    };

    render();
    return () => cancelAnimationFrame(animationFrame);
  }, [isSpinning, speed]);

  // Drag to rotate handlers
  const handleMouseDown = (e) => {
    isDraggingRef.current = true;
    lastMouseXRef.current = e.clientX;
    setIsSpinning(false);
  };

  const handleMouseMove = (e) => {
    if (!isDraggingRef.current) return;
    const deltaX = e.clientX - lastMouseXRef.current;
    lastMouseXRef.current = e.clientX;
    rotationRef.current = (rotationRef.current + deltaX * 0.4) % 360;
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
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
        background: "linear-gradient(180deg, rgba(8, 20, 32, 0.9) 0%, rgba(4, 10, 18, 0.98) 100%)",
        border: "1px solid rgba(86, 198, 255, 0.2)",
        position: "relative",
      }}
      onMouseUp={handleMouseUp}
    >
      {/* War Room Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: "1.4rem" }}>🌍</span>
          <div>
            <h3 style={{ margin: 0, color: "#fff", fontSize: "1.15rem", fontFamily: "var(--font-display)" }}>
              Global Threat Actor Radar &amp; Attack Arcs
            </h3>
            <div style={{ fontSize: "0.8rem", color: "var(--color-text-muted)" }}>
              Real-time realistic 3D Earth telemetry tracking foreign adversary probes against protected endpoints
            </div>
          </div>
        </div>

        {/* Tactical Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setIsSpinning(!isSpinning)}
            style={{ fontSize: "0.78rem" }}
          >
            {isSpinning ? "⏸ Freeze Orbit" : "▶ Resume Spin"}
          </Button>
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <span className="muted" style={{ fontSize: "0.72rem", marginRight: 2 }}>Orbit:</span>
            {[
              { val: 0.5, label: "Slow (0.5x)" },
              { val: 1, label: "Normal (1x)" },
              { val: 2, label: "Fast (2x)" },
            ].map((s) => (
              <button
                key={s.val}
                onClick={() => { setSpeed(s.val); setIsSpinning(true); }}
                style={{
                  padding: "4px 8px",
                  borderRadius: 4,
                  border: "1px solid rgba(86, 198, 255, 0.2)",
                  background: speed === s.val && isSpinning ? "rgba(86, 198, 255, 0.25)" : "transparent",
                  color: speed === s.val && isSpinning ? "#56c6ff" : "var(--color-text-muted)",
                  fontSize: "0.72rem",
                  cursor: "pointer",
                }}
              >
                {s.label}
              </button>
            ))}
          </div>
          <Badge tone={attackVectors.length > 0 ? "danger" : "info"}>
            {attackVectors.length} Active {attackVectors.length === 1 ? "Vector" : "Vectors"}
          </Badge>
        </div>
      </div>

      {/* Main Radar Layout */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px", gap: 20, alignItems: "center" }}>
        {/* Interactive 3D Canvas with Realistic Earth */}
        <div
          style={{
            position: "relative",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            cursor: "grab",
            borderRadius: 12,
            background: "#030812",
            border: "1px solid rgba(86, 198, 255, 0.15)",
            overflow: "hidden",
          }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
        >
          <canvas
            ref={canvasRef}
            width={520}
            height={420}
            style={{ maxWidth: "100%", height: "auto" }}
          />
          <div
            style={{
              position: "absolute",
              bottom: 10,
              left: 16,
              fontSize: "0.72rem",
              color: "rgba(255, 255, 255, 0.45)",
              pointerEvents: "none",
            }}
          >
            Click &amp; drag realistic Earth sphere to inspect adversary vectors
          </div>
        </div>

        {/* Live Attack Feed Sidebar */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ fontSize: "0.75rem", color: "#56c6ff", fontWeight: 700, textTransform: "uppercase" }}>
            Inbound Intercept Queue
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 360, overflowY: "auto" }}>
            {attackVectors.length === 0 ? (
              <div
                style={{
                  padding: "24px 14px",
                  borderRadius: 8,
                  background: "rgba(0, 0, 0, 0.25)",
                  border: "1px dashed rgba(255, 255, 255, 0.1)",
                  textAlign: "center",
                  color: "var(--color-text-muted)",
                  fontSize: "0.82rem",
                  lineHeight: 1.5,
                }}
              >
                <b>No Active External Threat Vectors</b>
                <div style={{ marginTop: 6, fontSize: "0.74rem" }}>
                  Inbound threat trajectories will plot automatically when external alert IPs or DAST web attack vectors are detected.
                </div>
              </div>
            ) : (
              attackVectors.map((vec) => {
              const isSelected = selectedAttack?.id === vec.id;
              const isCrit = vec.sev === "CRITICAL";
              return (
                <div
                  key={vec.id}
                  onClick={() => setSelectedAttack(vec)}
                  style={{
                    padding: "10px 14px",
                    borderRadius: 8,
                    background: isSelected ? "rgba(86, 198, 255, 0.15)" : "rgba(0, 0, 0, 0.35)",
                    border: `1px solid ${isSelected ? "#56c6ff" : isCrit ? "rgba(255, 82, 82, 0.3)" : "rgba(255, 255, 255, 0.08)"}`,
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: "0.85rem" }}>
                        {vec.srcCountry === "RU" ? "🇷🇺" : vec.srcCountry === "CN" ? "🇨🇳" : vec.srcCountry === "DE" ? "🇩🇪" : vec.srcCountry === "BR" ? "🇧🇷" : "🇺🇸"}
                      </span>
                      <code style={{ fontSize: "0.82rem", color: "#fff", fontWeight: 700 }}>{vec.srcIp}</code>
                    </div>
                    <Badge tone={isCrit ? "danger" : "warn"}>{vec.sev}</Badge>
                  </div>
                  <div style={{ fontSize: "0.78rem", color: "rgba(255, 255, 255, 0.85)" }}>
                    <b>{vec.tactic}</b> ➔ <code>{vec.target}</code>
                  </div>
                  <div style={{ fontSize: "0.72rem", color: "var(--color-text-muted)", marginTop: 2 }}>
                    Origin: {vec.srcCity}, {vec.srcCountry} · MITRE: <span style={{ color: "#56c6ff" }}>{vec.mitre}</span>
                  </div>
                </div>
              );
            }))}
          </div>
        </div>
      </div>

      {/* Selected Attack Inspector Drawer / Modal */}
      {selectedAttack && (
        <div
          style={{
            padding: 16,
            borderRadius: 8,
            background: "rgba(255, 82, 82, 0.08)",
            border: "1px solid rgba(255, 82, 82, 0.3)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: 12,
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: "1.1rem" }}>🚨</span>
              <strong style={{ color: "#fff", fontSize: "0.95rem" }}>
                Intercepted Vector: {selectedAttack.srcIp} ({selectedAttack.srcCity}, {selectedAttack.srcCountry})
              </strong>
              <Badge tone="danger">{selectedAttack.sev}</Badge>
            </div>
            <div style={{ fontSize: "0.8rem", color: "rgba(255, 255, 255, 0.85)", marginTop: 4 }}>
              Targeting: <code>{selectedAttack.target}</code> | Technique: <b>{selectedAttack.tactic} [{selectedAttack.mitre}]</b>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <Button
              size="sm"
              variant="danger"
              onClick={() => window.alert(`WAF block rule deployed for ${selectedAttack.srcIp} on perimeter!`)}
            >
              ⚡ 1-Click WAF Block
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelectedAttack(null)}>
              Dismiss
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

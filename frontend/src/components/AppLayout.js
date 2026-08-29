import React, { useState, useEffect } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import ProwlerSidePanel from "./ProwlerSidePanel";
import CommandPalette from "./CommandPalette";
import LiveTelemetryTicker from "./LiveTelemetryTicker";

export default function AppLayout({ children, onLogout }) {
  const [prowlerOpen, setProwlerOpen] = useState(false);
  const [cmdPaletteOpen, setCmdPaletteOpen] = useState(false);

  // Global Cmd+K / Ctrl+K keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div className="soc-layout">
      <Sidebar onLogout={onLogout} onOpenProwler={() => setProwlerOpen(true)} />

      <div className="soc-layout__main" style={{ paddingBottom: 48 }}>
        {/* Top Global Command Search Trigger */}
        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            padding: "8px 24px 0",
            marginBottom: -8,
          }}
        >
          <button
            onClick={() => setCmdPaletteOpen(true)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "6px 14px",
              borderRadius: 8,
              background: "rgba(86, 198, 255, 0.08)",
              border: "1px solid rgba(86, 198, 255, 0.25)",
              color: "var(--color-text-muted)",
              fontSize: "0.82rem",
              cursor: "pointer",
              transition: "all 0.15s ease",
            }}
            title="Press Cmd+K or Ctrl+K to search"
          >
            <span>🔍 Search targets, alerts, or commands…</span>
            <kbd
              style={{
                background: "rgba(255, 255, 255, 0.12)",
                padding: "2px 6px",
                borderRadius: 4,
                fontSize: "0.72rem",
                color: "#fff",
                fontWeight: 700,
              }}
            >
              ⌘K
            </kbd>
          </button>
        </div>

        {children || <Outlet />}
      </div>

      {/* Floating Prowler Posture Launcher */}
      <button
        onClick={() => setProwlerOpen(true)}
        style={{
          position: "fixed",
          bottom: 46,
          right: 24,
          zIndex: 900,
          background: "linear-gradient(135deg, #0e2a42 0%, #081624 100%)",
          color: "#56c6ff",
          border: "1px solid rgba(86, 198, 255, 0.4)",
          borderRadius: 999,
          padding: "10px 18px",
          display: "flex",
          alignItems: "center",
          gap: 8,
          boxShadow: "0 8px 24px rgba(0,0,0,0.5), 0 0 16px rgba(86,198,255,0.2)",
          cursor: "pointer",
          fontWeight: 700,
          fontSize: "0.85rem",
          letterSpacing: "0.02em",
          transition: "transform 0.2s ease, box-shadow 0.2s ease",
        }}
        title="Open Prowler Cloud Security Posture (CSPM) Panel"
        onMouseEnter={(e) => {
          e.currentTarget.style.transform = "translateY(-2px)";
          e.currentTarget.style.boxShadow = "0 12px 30px rgba(0,0,0,0.6), 0 0 24px rgba(86,198,255,0.4)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.transform = "none";
          e.currentTarget.style.boxShadow = "0 8px 24px rgba(0,0,0,0.5), 0 0 16px rgba(86,198,255,0.2)";
        }}
      >
        <span style={{ fontSize: "1.1rem" }}>🛡️</span>
        <span>Prowler Posture</span>
      </button>

      {/* Prowler Side Panel */}
      <ProwlerSidePanel isOpen={prowlerOpen} onClose={() => setProwlerOpen(false)} />

      {/* Spotlight Command Palette (Cmd + K) */}
      <CommandPalette
        isOpen={cmdPaletteOpen}
        onClose={() => setCmdPaletteOpen(false)}
        onOpenProwler={() => {
          setCmdPaletteOpen(false);
          setProwlerOpen(true);
        }}
      />

      {/* Bottom Live Telemetry & Log Stream HUD */}
      <LiveTelemetryTicker />
    </div>
  );
}

import React, { useState } from "react";
import Sidebar from "./Sidebar";
import ProwlerSidePanel from "./ProwlerSidePanel";

export default function AppLayout({ children, onLogout }) {
  const [prowlerOpen, setProwlerOpen] = useState(false);

  return (
    <div className="soc-layout">
      <Sidebar onLogout={onLogout} onOpenProwler={() => setProwlerOpen(true)} />
      <div className="soc-layout__main">{children}</div>

      {/* Floating Prowler Posture Launcher */}
      <button
        onClick={() => setProwlerOpen(true)}
        style={{
          position: "fixed",
          bottom: 24,
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
    </div>
  );
}

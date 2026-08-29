import React, { useEffect, useState, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api";
import { THEMES, applyTheme, saveStoredPreferences } from "../theme";

export default function CommandPalette({ isOpen, onClose, onOpenProwler }) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [targets, setTargets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const navigate = useNavigate();
  const inputRef = useRef(null);

  // Fetch quick search data on open
  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);

      // Async prefetch targets & alerts
      api.get("/web-targets").then((res) => {
        setTargets(res.data.targets || []);
      }).catch(() => {});

      api.get("/alerts?limit=10").then((res) => {
        setAlerts(res.data.alerts || res.data || []);
      }).catch(() => {});
    }
  }, [isOpen]);

  const defaultNavigationItems = [
    { id: "nav-dash", label: "Executive SOC Dashboard", category: "Navigation", icon: "📊", action: () => navigate("/dashboard") },
    { id: "nav-alerts", label: "Live Detections & Alerts", category: "Navigation", icon: "🚨", action: () => navigate("/alerts") },
    { id: "nav-hunting", label: "Threat Hunting Workspace", category: "Navigation", icon: "🎯", action: () => navigate("/hunting") },
    { id: "nav-webscan", label: "Web Security & DAST Scanner", category: "Navigation", icon: "🌐", action: () => navigate("/webscan") },
    { id: "nav-intel", label: "Threat Intelligence & IOCs", category: "Navigation", icon: "⚡", action: () => navigate("/intelligence") },
    { id: "nav-cases", label: "Incident Case Management", category: "Navigation", icon: "📁", action: () => navigate("/cases") },
    { id: "nav-settings", label: "Platform Settings & Integrations", category: "Navigation", icon: "⚙️", action: () => navigate("/settings") },
  ];

  const actionItems = [
    {
      id: "act-prowler",
      label: "Open Prowler Cloud Security Posture (CSPM)",
      category: "Actions",
      icon: "🛡️",
      action: () => {
        if (onOpenProwler) onOpenProwler();
      },
    },
    {
      id: "act-scan",
      label: "Start New Web Target Assessment",
      category: "Actions",
      icon: "⚡",
      action: () => navigate("/webscan/scans"),
    },
    {
      id: "act-ioc",
      label: "Register New Threat IOC / IP Indicator",
      category: "Actions",
      icon: "➕",
      action: () => navigate("/intelligence"),
    },
    ...THEMES.map((theme) => ({
      id: `act-theme-${theme.id}`,
      label: `Switch Theme to ${theme.name}`,
      category: "Themes",
      icon: "🎨",
      action: () => {
        applyTheme(theme.id);
        saveStoredPreferences({ theme: theme.id });
      },
    })),
  ];

  const targetItems = targets.map((t) => ({
    id: `target-${t.id}`,
    label: `${t.name} (${t.url})`,
    category: "Monitored Targets",
    icon: "🎯",
    action: () => navigate(`/webscan/targets/${t.id}`),
  }));

  const alertItems = (Array.isArray(alerts) ? alerts : []).map((a) => ({
    id: `alert-${a.id}`,
    label: `[${a.severity || "ALERT"}] ${a.title || a.signature || "Threat Detection"}`,
    category: "Recent Alerts",
    icon: "⚠️",
    action: () => navigate(`/alerts`),
  }));

  const allItems = useMemo(() => {
    return [...defaultNavigationItems, ...actionItems, ...targetItems, ...alertItems];
  }, [targets, alerts]);

  const filteredItems = useMemo(() => {
    if (!query.trim()) return allItems.slice(0, 15);
    const q = query.toLowerCase();
    return allItems
      .filter((item) => item.label.toLowerCase().includes(q) || item.category.toLowerCase().includes(q))
      .slice(0, 20);
  }, [allItems, query]);

  // Handle keyboard navigation
  const handleKeyDown = (e) => {
    if (e.key === "Escape") {
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filteredItems.length || 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + (filteredItems.length || 1)) % (filteredItems.length || 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        filteredItems[selectedIndex].action();
        onClose();
      }
    }
  };

  if (!isOpen) return null;

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 9999,
        background: "rgba(2, 6, 12, 0.78)",
        backdropFilter: "blur(6px)",
        display: "flex",
        justifyContent: "center",
        alignItems: "flex-start",
        paddingTop: "12vh",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 640,
          background: "var(--bg-1, #0c1420)",
          borderRadius: 14,
          border: "1px solid rgba(86, 198, 255, 0.35)",
          boxShadow: "0 24px 64px rgba(0, 0, 0, 0.8), 0 0 32px rgba(86, 198, 255, 0.15)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
        }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div
          style={{
            padding: "16px 20px",
            borderBottom: "1px solid rgba(86, 198, 255, 0.18)",
            display: "flex",
            alignItems: "center",
            gap: 12,
            background: "rgba(86, 198, 255, 0.04)",
          }}
        >
          <span style={{ fontSize: "1.2rem", color: "#56c6ff" }}>🔍</span>
          <input
            ref={inputRef}
            placeholder="Type a command, jump to target, search alerts, or switch theme..."
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            style={{
              flex: 1,
              background: "transparent",
              border: "none",
              outline: "none",
              color: "#fff",
              fontSize: "1.05rem",
              fontFamily: "var(--font-body)",
            }}
          />
          <div
            style={{
              padding: "2px 8px",
              borderRadius: 6,
              background: "rgba(255, 255, 255, 0.1)",
              color: "var(--color-text-muted)",
              fontSize: "0.75rem",
              fontWeight: 700,
            }}
          >
            ESC
          </div>
        </div>

        {/* Results List */}
        <div style={{ maxHeight: 380, overflowY: "auto", padding: "8px 0" }}>
          {filteredItems.length === 0 ? (
            <div style={{ padding: 24, textAlign: "center", color: "var(--color-text-muted)" }}>
              No commands, targets, or alerts found for "{query}".
            </div>
          ) : (
            filteredItems.map((item, idx) => {
              const isSelected = idx === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={() => {
                    item.action();
                    onClose();
                  }}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  style={{
                    padding: "10px 20px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    background: isSelected ? "rgba(86, 198, 255, 0.16)" : "transparent",
                    borderLeft: `3px solid ${isSelected ? "#56c6ff" : "transparent"}`,
                    cursor: "pointer",
                    transition: "background 0.1s ease",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <span style={{ fontSize: "1.1rem" }}>{item.icon}</span>
                    <span style={{ fontSize: "0.9rem", color: isSelected ? "#fff" : "rgba(255, 255, 255, 0.85)", fontWeight: isSelected ? 600 : 400 }}>
                      {item.label}
                    </span>
                  </div>
                  <span
                    style={{
                      fontSize: "0.72rem",
                      textTransform: "uppercase",
                      color: isSelected ? "#56c6ff" : "var(--color-text-muted)",
                      fontWeight: 700,
                      letterSpacing: "0.04em",
                    }}
                  >
                    {item.category}
                  </span>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Shortcut Guide */}
        <div
          style={{
            padding: "10px 20px",
            background: "rgba(0, 0, 0, 0.4)",
            borderTop: "1px solid rgba(255, 255, 255, 0.08)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontSize: "0.75rem",
            color: "var(--color-text-muted)",
          }}
        >
          <div style={{ display: "flex", gap: 14 }}>
            <span>↑↓ to navigate</span>
            <span>↵ to select</span>
            <span>esc to close</span>
          </div>
          <div>DecodeX Spotlight Command Engine</div>
        </div>
      </div>
    </div>
  );
}

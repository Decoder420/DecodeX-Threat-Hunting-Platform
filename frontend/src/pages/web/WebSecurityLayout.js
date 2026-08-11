import React from "react";
import { NavLink, Outlet } from "react-router-dom";

const TABS = [
  { to: "/webscan", end: true, label: "Overview" },
  { to: "/webscan/targets", label: "Targets" },
  { to: "/webscan/scans", label: "Scans" },
  { to: "/webscan/findings", label: "Findings" },
  { to: "/webscan/attack-surface", label: "Attack Surface" },
  { to: "/webscan/health", label: "Scanner Health" },
];

export default function WebSecurityLayout() {
  return (
    <div className="page-shell websec">
      <header className="websec__header">
        <div>
          <h1>Web Security</h1>
          <p className="page-shell__copy">
            Authorized application security assessments — discovery, passive analysis,
            optional Nuclei/Nmap/ZAP, risk scoring, and SOC integration.
          </p>
        </div>
      </header>
      <nav className="websec__tabs" aria-label="Web Security sections">
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) =>
              `websec__tab${isActive ? " is-active" : ""}`
            }
          >
            {tab.label}
          </NavLink>
        ))}
      </nav>
      <Outlet />
    </div>
  );
}

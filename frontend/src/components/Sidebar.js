import { NavLink } from "react-router-dom";
import { canAccessAdminPanel, getStoredUser, hasPermission } from "../auth";
import Button from "./ui/Button";

const LINKS = [
  { to: "/dashboard", label: "Dashboard", permission: "dashboard.read" },
  { to: "/alerts", label: "Alerts", permission: "alerts.read" },
  { to: "/hunting", label: "Hunting", permission: "events.read" },
  { to: "/cases", label: "Cases", permission: "cases.read" },
  { to: "/intelligence", label: "Intelligence", permission: "ioc.read" },
  { to: "/webscan", label: "Web Security", permission: "webscan.read" },
  { to: "/reports", label: "Reports", permission: "reports.read" },
  { to: "/settings", label: "Settings", permission: "dashboard.read" },
  { to: "/admin/users", label: "Admin Users", permission: "users.read" },
  { to: "/admin/audit", label: "Audit Logs", permission: "audit.read" },
  { to: "/admin/console", label: "Admin Console", permission: "users.read" },
];

export default function Sidebar({ onLogout, onOpenProwler }) {
  const user = getStoredUser();
  const visible = LINKS.filter((link) => {
    if (link.to.startsWith("/admin") && !canAccessAdminPanel(user) && link.permission !== "audit.read") {
      // audit is admin-only via permission
    }
    if (link.to === "/hunting" && user?.role === "viewer") return false;
    if (link.to === "/cases" && !hasPermission("cases.read", user)) return false;
    if (link.to === "/webscan" && !hasPermission("webscan.read", user)) return false;
    return hasPermission(link.permission, user);
  });

  return (
    <aside className="soc-sidebar">
      <div className="soc-sidebar__brand">
        <div className="app-nav__mark" aria-hidden style={{ overflow: "hidden", padding: 0 }}>
          <img
            src={`${process.env.PUBLIC_URL || ""}/logo192.png`}
            alt="DecodeX"
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        </div>
        <div>
          <div className="soc-sidebar__title">DecodeX</div>
          <div className="soc-sidebar__subtitle">Threat Hunting SOC</div>
        </div>
      </div>
      <nav className="soc-sidebar__nav" aria-label="Main Navigation">
        {visible.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `soc-sidebar__link${isActive ? " is-active" : ""}`
            }
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
      <div className="soc-sidebar__footer">
        {onOpenProwler ? (
          <button
            onClick={onOpenProwler}
            style={{
              width: "100%",
              marginBottom: 8,
              padding: "7px 12px",
              borderRadius: 6,
              background: "rgba(86, 198, 255, 0.08)",
              border: "1px solid rgba(86, 198, 255, 0.3)",
              color: "#56c6ff",
              fontSize: "0.78rem",
              fontWeight: 700,
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: 6,
            }}
          >
            <span>🛡️</span>
            <span>Prowler Posture</span>
          </button>
        ) : null}
        {!hasPermission("alerts.write", user) ? (
          <div className="soc-sidebar__hint">Read-only session</div>
        ) : null}
        <Button size="sm" variant="danger" block onClick={onLogout}>
          Logout
        </Button>
        <div
          className="soc-sidebar__hint"
          style={{ fontSize: "0.68rem", opacity: 0.7, marginTop: 8, textAlign: "center" }}
        >
          DecodeX Security Technologies
        </div>
      </div>
    </aside>
  );
}

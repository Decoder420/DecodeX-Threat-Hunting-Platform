import React, { useEffect, useRef } from "react";
import gsap from "gsap";
import Button from "./ui/Button";
import { canAccessAdminPanel, getStoredUser, hasPermission } from "../auth";
import { PermissionGate } from "./PermissionGate";

export default function Navbar({
  onNavigate,
  onLogout,
  currentView = "dashboard",
  currentUser,
}) {
  const navRef = useRef(null);
  const user = currentUser || getStoredUser();
  const showAdmin = canAccessAdminPanel(user);

  useEffect(() => {
    if (!navRef.current) return undefined;
    const ctx = gsap.context(() => {
      gsap.fromTo(
        navRef.current,
        { y: -18, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.55, ease: "power3.out" }
      );
    }, navRef);
    return () => ctx.revert();
  }, []);

  // If the user loses admin access while on the admin view, bounce home.
  useEffect(() => {
    if (currentView === "admin" && !showAdmin && onNavigate) {
      onNavigate("dashboard");
    }
  }, [currentView, showAdmin, onNavigate]);

  return (
    <nav ref={navRef} className="app-nav">
      <div className="app-nav__brand">
        <div className="app-nav__mark" aria-hidden style={{ overflow: "hidden", padding: 0 }}>
          <img
            src={`${process.env.PUBLIC_URL || ""}/logo192.png`}
            alt="DecodeX"
            style={{ width: "100%", height: "100%", objectFit: "cover" }}
          />
        </div>
        <div>
          <h2 className="app-nav__title">DecodeX SOC</h2>
          <p className="app-nav__subtitle">
            {user
              ? `${user.username} · ${user.role}`
              : "Operations Console"}
          </p>
        </div>
      </div>

      <div className="app-nav__actions">
        <PermissionGate permission="dashboard.read">
          <Button
            size="sm"
            className={currentView === "dashboard" ? "is-active" : ""}
            onClick={() => onNavigate("dashboard")}
          >
            Dashboard
          </Button>
        </PermissionGate>

        {showAdmin ? (
          <Button
            size="sm"
            className={currentView === "admin" ? "is-active" : ""}
            onClick={() => onNavigate("admin")}
          >
            Admin
          </Button>
        ) : null}

        {hasPermission("alerts.write", user) ? null : (
          <span
            style={{
              fontSize: 12,
              color: "var(--text-muted)",
              alignSelf: "center",
              marginRight: 4,
            }}
          >
            Read-only
          </span>
        )}

        <Button size="sm" variant="danger" onClick={onLogout}>
          Logout
        </Button>
      </div>
    </nav>
  );
}

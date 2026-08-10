import React, { useEffect, useRef } from "react";
import gsap from "gsap";
import Button from "./ui/Button";

export default function Navbar({ onNavigate, onLogout, currentView = "dashboard" }) {
  const navRef = useRef(null);

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

  return (
    <nav ref={navRef} className="app-nav">
      <div className="app-nav__brand">
        <div className="app-nav__mark" aria-hidden>
          TH
        </div>
        <div>
          <h2 className="app-nav__title">Threat Hunting SIEM</h2>
          <p className="app-nav__subtitle">Operations Console</p>
        </div>
      </div>

      <div className="app-nav__actions">
        <Button
          size="sm"
          className={currentView === "dashboard" ? "is-active" : ""}
          onClick={() => onNavigate("dashboard")}
        >
          Dashboard
        </Button>
        <Button
          size="sm"
          className={currentView === "admin" ? "is-active" : ""}
          onClick={() => onNavigate("admin")}
        >
          Admin
        </Button>
        <Button size="sm" variant="danger" onClick={onLogout}>
          Logout
        </Button>
      </div>
    </nav>
  );
}

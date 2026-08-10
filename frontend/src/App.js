import React, { useEffect, useRef, useState } from "react";
import gsap from "gsap";
import Dashboard from "./pages/Dashboard";
import api from "./api";
import Button from "./components/ui/Button";
import "./styles/theme.css";

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(
    !!localStorage.getItem("token")
  );
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const cardRef = useRef(null);

  useEffect(() => {
    if (isAuthenticated || !cardRef.current) return undefined;
    const ctx = gsap.context(() => {
      gsap.fromTo(
        cardRef.current,
        { y: 28, opacity: 0, scale: 0.98 },
        { y: 0, opacity: 1, scale: 1, duration: 0.75, ease: "power3.out" }
      );
      gsap.fromTo(
        ".login-shell__grid",
        { opacity: 0 },
        { opacity: 1, duration: 1.1, ease: "power1.out" }
      );
    });
    return () => ctx.revert();
  }, [isAuthenticated]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await api.post("/auth/login", { username, password });
      localStorage.setItem("token", res.data.token);
      localStorage.setItem("user", JSON.stringify(res.data.user));
      setIsAuthenticated(true);
    } catch (err) {
      setError(
        err.response && err.response.status === 401
          ? "Invalid username or password."
          : "Login failed — is the backend running?"
      );
      if (cardRef.current) {
        gsap.fromTo(
          cardRef.current,
          { x: -8 },
          { x: 0, duration: 0.35, ease: "elastic.out(1, 0.4)" }
        );
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    const token = localStorage.getItem("token");
    try {
      if (token) {
        await api.post(
          "/auth/logout",
          {},
          { headers: { Authorization: `Bearer ${token}` } }
        );
      }
    } catch {
      // Still clear local session even if revoke fails.
    }
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return (
      <div className="login-shell">
        <video
          className="login-shell__video"
          autoPlay
          muted
          loop
          playsInline
          aria-hidden
        >
          <source src={`${process.env.PUBLIC_URL || ""}/loginbg.mp4`} type="video/mp4" />
        </video>
        <div className="login-shell__overlay" aria-hidden />
        <div className="login-shell__grid" aria-hidden />
        <form ref={cardRef} className="surface login-card" onSubmit={handleLogin}>
          <div className="login-card__eyebrow">Threat Hunting Platform</div>
          <h1>SIEM Access</h1>
          <p className="login-card__copy">
            Sign in to the operations console for live alerts, MITRE context, and
            incident response.
          </p>

          <label className="field">
            <span className="field__label">Username</span>
            <input
              className="field__input"
              type="text"
              placeholder="admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>

          <label className="field">
            <span className="field__label">Password</span>
            <input
              className="field__input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>

          {error ? <div className="login-card__error">{error}</div> : null}

          <Button type="submit" variant="primary" block disabled={loading}>
            {loading ? "Signing in..." : "Enter Console"}
          </Button>
        </form>
      </div>
    );
  }

  return <Dashboard onLogout={handleLogout} />;
}

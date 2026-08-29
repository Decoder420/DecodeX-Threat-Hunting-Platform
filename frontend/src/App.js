import React, { useEffect, useRef, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import gsap from "gsap";
import Dashboard from "./pages/Dashboard";
import AlertsPage from "./pages/AlertsPage";
import CasesPage from "./pages/CasesPage";
import HuntingPage from "./pages/HuntingPage";
import IntelligencePage from "./pages/IntelligencePage";
import WebSecurityLayout from "./pages/web/WebSecurityLayout";
import WebOverviewPage from "./pages/web/WebOverviewPage";
import WebTargetsPage from "./pages/web/WebTargetsPage";
import WebTargetDetailPage from "./pages/web/WebTargetDetailPage";
import WebScansPage from "./pages/web/WebScansPage";
import WebFindingsPage from "./pages/web/WebFindingsPage";
import WebAttackSurfacePage from "./pages/web/WebAttackSurfacePage";
import WebsiteMapPage from "./pages/web/WebsiteMapPage";
import WebScannerHealthPage from "./pages/web/WebScannerHealthPage";
import ReportsPage from "./pages/ReportsPage";
import SettingsPage from "./pages/SettingsPage";
import AdminUsersPage from "./pages/AdminUsersPage";
import AdminAuditPage from "./pages/AdminAuditPage";
import AppLayout from "./components/AppLayout";
import ProtectedRoute from "./components/ProtectedRoute";
import { getMe, login as apiLogin, logout as apiLogout } from "./api";
import {
  clearSession,
  getStoredToken,
  getStoredUser,
  setSession,
} from "./auth";
import Button from "./components/ui/Button";
import "./styles/theme.css";

function LoginScreen({ onSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const cardRef = useRef(null);

  useEffect(() => {
    if (!cardRef.current) return undefined;
    const ctx = gsap.context(() => {
      gsap.fromTo(
        cardRef.current,
        { y: 28, opacity: 0, scale: 0.98 },
        { y: 0, opacity: 1, scale: 1, duration: 0.75, ease: "power3.out" }
      );
    });
    return () => ctx.revert();
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await apiLogin(username, password);
      setSession(res.data.token, res.data.user);
      setPassword("");
      onSuccess(res.data.user);
    } catch (err) {
      const payload = err.response && err.response.data && err.response.data.error;
      const message =
        typeof payload === "object" && payload && payload.message
          ? payload.message
          : typeof payload === "string"
            ? payload
            : null;
      setError(
        err.response && err.response.status === 401
          ? message || "Invalid username or password."
          : message || "Login failed — is the backend running?"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-shell">
      <video className="login-shell__video" autoPlay muted loop playsInline aria-hidden>
        <source src={`${process.env.PUBLIC_URL || ""}/loginbg.mp4`} type="video/mp4" />
      </video>
      <div className="login-shell__overlay" aria-hidden />
      <div className="login-shell__grid" aria-hidden />
      <form ref={cardRef} className="surface login-card" onSubmit={handleLogin}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 16 }}>
          <img
            src={`${process.env.PUBLIC_URL || ""}/decodex_emblem.png`}
            alt="DecodeX Logo"
            style={{
              width: 130,
              height: "auto",
              borderRadius: 12,
              border: "1px solid rgba(86, 198, 255, 0.25)",
              boxShadow: "0 8px 24px rgba(0, 0, 0, 0.4)",
            }}
          />
        </div>
        <div className="login-card__eyebrow">DecodeX Security Technologies</div>
        <h1>DecodeX Console</h1>
        <p className="login-card__copy">
          Sign in for live alerts, MITRE context, cases, and authorized response.
        </p>
        <label className="field">
          <span className="field__label">Username</span>
          <input
            className="field__input"
            type="text"
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

export default function App() {
  const [sessionUser, setSessionUser] = useState(() => getStoredUser());
  const [isAuthenticated, setIsAuthenticated] = useState(() => !!getStoredToken());
  const [authReady, setAuthReady] = useState(!getStoredToken());

  useEffect(() => {
    const token = getStoredToken();
    if (!token) {
      setAuthReady(true);
      return undefined;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await getMe();
        if (cancelled) return;
        setSession(token, res.data);
        setSessionUser(res.data);
        setIsAuthenticated(true);
      } catch {
        if (cancelled) return;
        clearSession();
        setSessionUser(null);
        setIsAuthenticated(false);
      } finally {
        if (!cancelled) setAuthReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLogout = async () => {
    try {
      await apiLogout();
    } catch {
      // ignore
    }
    clearSession();
    setSessionUser(null);
    setIsAuthenticated(false);
  };

  if (!authReady) {
    return (
      <div className="loader-screen">
        <div>
          <div className="loader-orb" aria-hidden />
          <div style={{ fontFamily: "var(--font-display)", fontSize: "1.35rem" }}>
            Checking session…
          </div>
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter
      basename={process.env.PUBLIC_URL || "/"}
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <Routes>
        <Route
          path="/login"
          element={
            isAuthenticated ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <LoginScreen
                onSuccess={(user) => {
                  setSessionUser(user);
                  setIsAuthenticated(true);
                }}
              />
            )
          }
        />
        <Route
          path="/*"
          element={
            !isAuthenticated ? (
              <Navigate to="/login" replace />
            ) : (
              <AppLayout onLogout={handleLogout}>
                <Routes>
                  <Route
                    path="/dashboard"
                    element={
                      <ProtectedRoute permission="dashboard.read">
                        <Dashboard embedded onLogout={handleLogout} currentUser={sessionUser} />
                      </ProtectedRoute>
                    }
                  />
                  <Route path="/alerts" element={<ProtectedRoute permission="alerts.read"><AlertsPage /></ProtectedRoute>} />
                  <Route path="/hunting" element={<ProtectedRoute permission="events.read"><HuntingPage /></ProtectedRoute>} />
                  <Route path="/cases" element={<ProtectedRoute permission="cases.read"><CasesPage /></ProtectedRoute>} />
                  <Route path="/intelligence" element={<ProtectedRoute permission="ioc.read"><IntelligencePage /></ProtectedRoute>} />
                  <Route path="/webscan" element={<ProtectedRoute permission="webscan.read"><WebSecurityLayout /></ProtectedRoute>}>
                    <Route index element={<WebOverviewPage />} />
                    <Route path="targets" element={<WebTargetsPage />} />
                    <Route path="targets/:targetId" element={<WebTargetDetailPage />} />
                    <Route path="scans" element={<WebScansPage />} />
                    <Route path="findings" element={<WebFindingsPage />} />
                    <Route path="attack-surface" element={<WebAttackSurfacePage />} />
                    <Route path="map" element={<WebsiteMapPage />} />
                    <Route path="map/target/:targetId" element={<WebsiteMapPage />} />
                    <Route path="health" element={<WebScannerHealthPage />} />
                  </Route>
                  <Route path="/reports" element={<ProtectedRoute permission="reports.read"><ReportsPage /></ProtectedRoute>} />
                  <Route path="/settings" element={<ProtectedRoute permission="dashboard.read"><SettingsPage /></ProtectedRoute>} />
                  <Route path="/admin/users" element={<ProtectedRoute permission="users.read"><AdminUsersPage /></ProtectedRoute>} />
                  <Route path="/admin/audit" element={<ProtectedRoute permission="audit.read"><AdminAuditPage /></ProtectedRoute>} />
                  <Route path="/admin/console" element={<ProtectedRoute permission="users.read"><Dashboard embedded initialView="admin" onLogout={handleLogout} currentUser={sessionUser} /></ProtectedRoute>} />
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </AppLayout>
            )
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

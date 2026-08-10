import React, { useState } from "react";
import Dashboard from "./pages/Dashboard";
import api from "./api";

export default function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem("token"));
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

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
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        // Best-effort server-side revoke; proceed with local logout regardless.
        api.post("/auth/logout").catch(() => {});
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        setIsAuthenticated(false);
    };

    if (!isAuthenticated) {
        return (
            <div
                style={{
                    display: "flex",
                    justifyContent: "center",
                    alignItems: "center",
                    height: "100vh",
                    background: "#0f172a",
                    color: "white",
                }}
            >
                <form
                    onSubmit={handleLogin}
                    style={{
                        width: "320px",
                        padding: "40px",
                        background: "#1e293b",
                        borderRadius: "8px",
                        border: "1px solid #334155",
                        boxSizing: "border-box",
                    }}
                >
                    <h2 style={{ marginTop: 0, marginBottom: "25px" }}>SIEM Access</h2>

                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        autoComplete="username"
                        required
                        style={{
                            display: "block",
                            width: "100%",
                            boxSizing: "border-box",
                            margin: "10px 0",
                            padding: "10px",
                            background: "#0f172a",
                            border: "1px solid #334155",
                            borderRadius: "4px",
                            color: "white",
                        }}
                    />

                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="current-password"
                        required
                        style={{
                            display: "block",
                            width: "100%",
                            boxSizing: "border-box",
                            margin: "10px 0 20px",
                            padding: "10px",
                            background: "#0f172a",
                            border: "1px solid #334155",
                            borderRadius: "4px",
                            color: "white",
                        }}
                    />

                    {error && (
                        <div style={{ color: "#f87171", fontSize: "13px", marginBottom: "12px" }}>
                            {error}
                        </div>
                    )}

                    <button
                        type="submit"
                        disabled={loading}
                        style={{
                            width: "100%",
                            padding: "10px",
                            background: "#3b82f6",
                            color: "white",
                            border: "none",
                            borderRadius: "4px",
                            cursor: loading ? "default" : "pointer",
                            fontWeight: "bold",
                            opacity: loading ? 0.7 : 1,
                        }}
                    >
                        {loading ? "Signing in..." : "Login"}
                    </button>
                </form>
            </div>
        );
    }

    return <Dashboard onLogout={handleLogout} />;
}

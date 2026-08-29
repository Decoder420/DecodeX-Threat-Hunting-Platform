import React, { useEffect, useState, useMemo } from "react";
import { useNavigate, Link } from "react-router-dom";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";
import { hasPermission } from "../../auth";

export default function WebTargetsPage() {
  const canRun = hasPermission("webscan.run");
  const navigate = useNavigate();
  const [targets, setTargets] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState("ALL");
  const [authFilter, setAuthFilter] = useState("ALL");
  const [successMsg, setSuccessMsg] = useState("");
  const [form, setForm] = useState({
    name: "",
    url: "https://",
    owner: "",
    scope: "",
    environment: "lab",
  });
  const [busyId, setBusyId] = useState(null);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await webApi.getTargets();
      setTargets(res.data.targets || []);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load targets.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const create = async (e) => {
    e.preventDefault();
    setError("");
    try {
      await webApi.createTarget(form);
      setForm({ name: "", url: "https://", owner: "", scope: "", environment: "lab" });
      await load();
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to create target.");
    }
  };

  const authorize = async (id, name) => {
    const ok = window.confirm(
      `AUTHORIZE scanning of "${name}"?\n\n` +
        "Only confirm if you have explicit written permission to assess this asset. " +
        "Unauthorized scanning may be illegal."
    );
    if (!ok) return;
    setBusyId(id);
    setError("");
    try {
      await webApi.authorizeTarget(id);
      setSuccessMsg(`✓ Target "${name}" is now AUTHORIZED and ready for scanning!`);
      setTimeout(() => setSuccessMsg(""), 4000);
      await load();
    } catch (err) {
      setError(err.response?.data?.error?.message || "Authorization failed.");
    } finally {
      setBusyId(null);
    }
  };

  const disable = async (id, name) => {
    if (!window.confirm(`Disable and revoke target "${name || id}"?`)) return;
    setBusyId(id);
    setError("");
    try {
      await webApi.disableTarget(id);
      setSuccessMsg(`Target authorization revoked.`);
      setTimeout(() => setSuccessMsg(""), 4000);
      await load();
    } catch (err) {
      setError(err.response?.data?.error?.message || "Disable failed.");
    } finally {
      setBusyId(null);
    }
  };

  const filteredTargets = useMemo(() => {
    return targets.filter((t) => {
      const matchSearch =
        !search ||
        (t.name || "").toLowerCase().includes(search.toLowerCase()) ||
        (t.url || "").toLowerCase().includes(search.toLowerCase()) ||
        (t.owner || "").toLowerCase().includes(search.toLowerCase());

      const matchEnv =
        envFilter === "ALL" ||
        (t.environment || "").toLowerCase() === envFilter.toLowerCase();

      const matchAuth =
        authFilter === "ALL" ||
        (t.authorization_status || "").toLowerCase() === authFilter.toLowerCase();

      return matchSearch && matchEnv && matchAuth;
    });
  }, [targets, search, envFilter, authFilter]);

  return (
    <div className="websec__stack">
      {error ? <div className="surface websec__panel error-text">{error}</div> : null}
      {successMsg ? (
        <div
          className="surface websec__panel"
          style={{
            borderColor: "rgba(62, 224, 162, 0.4)",
            background: "rgba(62, 224, 162, 0.08)",
            color: "#3ee0a2",
            fontWeight: 600,
            fontSize: "0.9rem",
          }}
        >
          {successMsg}
        </div>
      ) : null}

      {/* REGISTER TARGET FORM */}
      {canRun ? (
        <form className="surface websec__panel" onSubmit={create}>
          <div className="websec__row">
            <div>
              <h2 style={{ margin: 0 }}>Register Web Target</h2>
              <p className="muted" style={{ margin: "4px 0 0" }}>
                Add new web applications or API hosts to the assessment inventory. New targets begin in PENDING state until authorization.
              </p>
            </div>
          </div>

          <div className="websec__form-grid" style={{ marginTop: 14 }}>
            <input
              className="field__input"
              placeholder="Target Asset Name (e.g. Production Portal)"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <input
              className="field__input"
              placeholder="Root URL (https://...)"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              required
            />
            <input
              className="field__input"
              placeholder="Asset Owner / Team"
              value={form.owner}
              onChange={(e) => setForm({ ...form, owner: e.target.value })}
            />
            <select
              className="field__input"
              value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value })}
            >
              <option value="lab">Lab / Internal</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
          </div>

          <div style={{ marginTop: 10 }}>
            <input
              className="field__input"
              placeholder="Testing Scope Restrictions / Out-of-bounds paths (optional)"
              value={form.scope}
              onChange={(e) => setForm({ ...form, scope: e.target.value })}
            />
          </div>

          <div className="websec__actions" style={{ marginTop: 12 }}>
            <Button type="submit" variant="primary">
              + Register Target
            </Button>
          </div>
        </form>
      ) : null}

      {/* TARGETS LIST & CONTROLS */}
      <div className="surface websec__panel">
        <div className="websec__row">
          <div>
            <h2 style={{ margin: 0 }}>Target Inventory ({filteredTargets.length})</h2>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Authorized web assets eligible for active crawling, OWASP ZAP spidering, and vulnerability scanning.
            </p>
          </div>
          <Button size="sm" onClick={load}>
            ↻ Refresh
          </Button>
        </div>

        {/* SEARCH & FILTERS */}
        <div style={{ display: "flex", gap: 12, marginTop: 14, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
          <input
            className="field__input"
            style={{ flex: "1 1 240px", minWidth: 200 }}
            placeholder="Search targets by name, URL, or owner..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span className="muted" style={{ fontSize: "0.85rem" }}>Environment:</span>
            <select
              className="field__input"
              style={{ width: "auto", padding: "6px 10px" }}
              value={envFilter}
              onChange={(e) => setEnvFilter(e.target.value)}
            >
              <option value="ALL">All Environments</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="lab">Lab / Internal</option>
            </select>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span className="muted" style={{ fontSize: "0.85rem" }}>Authorization:</span>
            <select
              className="field__input"
              style={{ width: "auto", padding: "6px 10px" }}
              value={authFilter}
              onChange={(e) => setAuthFilter(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="authorized">Authorized</option>
              <option value="pending">Pending</option>
              <option value="revoked">Revoked</option>
            </select>
          </div>
        </div>

        {loading ? (
          <p className="muted">Loading target registry…</p>
        ) : !filteredTargets.length ? (
          <p className="muted">No targets matching filter criteria.</p>
        ) : (
          <div className="websec__table-wrap">
            <table className="websec__table">
              <thead>
                <tr>
                  <th>Target Name</th>
                  <th>URL / Domain</th>
                  <th>Environment</th>
                  <th>Scope</th>
                  <th>Authorization</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredTargets.map((t) => (
                  <tr key={t.id}>
                    <td>
                      <Link
                        to={`/webscan/targets/${t.id}`}
                        style={{ color: "#fff", textDecoration: "none" }}
                      >
                        <strong style={{ fontSize: "0.95rem", color: "#56c6ff" }}>{t.name}</strong>
                      </Link>
                      <div className="muted" style={{ fontSize: "0.75rem" }}>
                        Owner: {t.owner || "Security Operations"}
                      </div>
                    </td>
                    <td className="websec__mono" style={{ color: "var(--accent, #3ee0a2)" }}>
                      {t.url}
                    </td>
                    <td>
                      <Badge
                        tone={
                          t.environment === "production"
                            ? "danger"
                            : t.environment === "staging"
                            ? "warn"
                            : "ok"
                        }
                      >
                        {t.environment || "lab"}
                      </Badge>
                    </td>
                    <td className="muted" style={{ fontSize: "0.8rem", maxWidth: 180 }}>
                      {t.scope || "Full domain testing"}
                    </td>
                    <td>
                      <Badge
                        tone={
                          (t.authorization_status || "").toUpperCase() === "AUTHORIZED"
                            ? "ok"
                            : (t.authorization_status || "").toUpperCase() === "REVOKED"
                            ? "danger"
                            : "warn"
                        }
                      >
                        {t.authorization_status}
                      </Badge>
                    </td>
                    <td className="websec__actions-cell" style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => navigate(`/webscan/targets/${t.id}`)}
                      >
                        🔍 Cockpit
                      </Button>

                      {(t.authorization_status || "").toUpperCase() === "AUTHORIZED" && canRun ? (
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={() => navigate(`/webscan/scans?target=${t.id}`)}
                        >
                          ⚡ Scan
                        </Button>
                      ) : null}

                      {(t.authorization_status || "").toUpperCase() !== "AUTHORIZED" && canRun ? (
                        <Button
                          size="sm"
                          disabled={busyId === t.id}
                          onClick={() => authorize(t.id, t.name)}
                        >
                          {busyId === t.id ? "Authorizing…" : "Authorize"}
                        </Button>
                      ) : null}

                      {(t.authorization_status || "").toUpperCase() === "AUTHORIZED" && canRun ? (
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={busyId === t.id}
                          onClick={() => disable(t.id, t.name)}
                        >
                          Revoke
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
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
    try {
      await webApi.authorizeTarget(id);
      await load();
    } catch (err) {
      setError(err.response?.data?.error?.message || "Authorization failed.");
    } finally {
      setBusyId(null);
    }
  };

  const disable = async (id) => {
    if (!window.confirm("Disable and revoke this target?")) return;
    setBusyId(id);
    try {
      await webApi.disableTarget(id);
      await load();
    } catch (err) {
      setError(err.response?.data?.error?.message || "Disable failed.");
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="websec__stack">
      {error ? <div className="surface websec__panel error-text">{error}</div> : null}

      {canRun ? (
        <form className="surface websec__panel" onSubmit={create}>
          <h2>Register target</h2>
          <p className="muted">
            New targets start as PENDING. Authorization is a separate, audited step.
          </p>
          <div className="websec__form-grid">
            <input
              className="field__input"
              placeholder="Name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <input
              className="field__input"
              placeholder="https://app.example.com"
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.target.value })}
              required
            />
            <input
              className="field__input"
              placeholder="Owner"
              value={form.owner}
              onChange={(e) => setForm({ ...form, owner: e.target.value })}
            />
            <input
              className="field__input"
              placeholder="Scope (paths/hosts)"
              value={form.scope}
              onChange={(e) => setForm({ ...form, scope: e.target.value })}
            />
            <select
              className="field__input"
              value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value })}
            >
              <option value="lab">lab</option>
              <option value="staging">staging</option>
              <option value="production">production</option>
            </select>
            <Button type="submit" variant="primary">
              Add target
            </Button>
          </div>
        </form>
      ) : null}

      <div className="surface websec__panel">
        <h2>Targets</h2>
        {loading ? <div className="muted">Loading…</div> : null}
        {!loading && !targets.length ? (
          <div className="muted">No targets registered.</div>
        ) : null}
        <div className="websec__table-wrap">
          <table className="websec__table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Authorization</th>
                <th>Owner</th>
                <th>Env</th>
                <th>Last scan</th>
                <th>Risk</th>
                <th>Findings</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id}>
                  <td>
                    <strong>{t.name}</strong>
                    <div className="muted websec__mono">{t.url}</div>
                  </td>
                  <td>
                    <Badge tone={t.authorization_status === "AUTHORIZED" ? "ok" : "warn"}>
                      {t.authorization_status}
                    </Badge>
                  </td>
                  <td>{t.owner || "—"}</td>
                  <td>{t.environment || "lab"}</td>
                  <td>{t.last_scan ? new Date(t.last_scan).toLocaleString() : "—"}</td>
                  <td>{t.risk_score ?? 0}</td>
                  <td>{t.findings_count ?? 0}</td>
                  <td>{t.enabled ? t.last_status || "ready" : "disabled"}</td>
                  <td className="websec__actions-cell">
                    {canRun && t.authorization_status !== "AUTHORIZED" ? (
                      <Button
                        size="sm"
                        disabled={busyId === t.id}
                        onClick={() => authorize(t.id, t.name)}
                      >
                        Authorize
                      </Button>
                    ) : null}
                    {canRun && t.authorization_status === "AUTHORIZED" && t.enabled ? (
                      <Button
                        size="sm"
                        variant="primary"
                        onClick={() => navigate(`/webscan/scans?target=${t.id}`)}
                      >
                        Scan
                      </Button>
                    ) : null}
                    <Button
                      size="sm"
                      onClick={() => navigate(`/webscan/map/target/${t.id}`)}
                    >
                      Website Map
                    </Button>
                    {canRun && t.enabled ? (
                      <Button size="sm" variant="danger" onClick={() => disable(t.id)}>
                        Disable
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

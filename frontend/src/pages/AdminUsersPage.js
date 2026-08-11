import React, { useEffect, useState } from "react";
import {
  activateUser,
  createUser,
  deactivateUser,
  listUsers,
  resetUserPassword,
  updateUserRole,
} from "../api";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";

function apiMessage(err, fallback) {
  return err?.response?.data?.error?.message || err?.message || fallback;
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState({
    username: "",
    password: "",
    role: "analyst",
  });

  const load = async () => {
    const res = await listUsers();
    setUsers(res.data.users || []);
  };

  useEffect(() => {
    load().catch((err) => setError(apiMessage(err, "Failed to load users.")));
  }, []);

  const onCreate = async (e) => {
    e.preventDefault();
    setError("");
    setNotice("");
    if ((form.password || "").length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    try {
      await createUser(form);
      setForm({ username: "", password: "", role: "analyst" });
      setNotice("User created.");
      await load();
    } catch (err) {
      setError(apiMessage(err, "Failed to create user."));
    }
  };

  const onResetPassword = async (user) => {
    setError("");
    setNotice("");
    const password = window.prompt(`New password for ${user.username} (minimum 8 characters)`);
    if (password == null) return;
    if (password.trim().length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    try {
      await resetUserPassword(user.id, password);
      setNotice(`Password reset for ${user.username}. Their sessions were revoked.`);
      await load();
    } catch (err) {
      setError(apiMessage(err, "Password reset failed."));
    }
  };

  return (
    <div className="page-shell">
      <h1>User Management</h1>
      <p className="page-shell__copy">
        Admin-only account lifecycle controls with last-admin protection.
        Passwords must be at least 8 characters.
      </p>

      {error ? <div className="surface websec__panel error-text">{error}</div> : null}
      {notice ? <div className="surface websec__panel muted">{notice}</div> : null}

      <form className="surface" style={{ padding: 16, marginBottom: 16 }} onSubmit={onCreate}>
        <h2>Create user</h2>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input
            className="field__input"
            placeholder="Username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            required
          />
          <input
            className="field__input"
            type="password"
            placeholder="Password (8+)"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            minLength={8}
            required
          />
          <select
            className="field__select"
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
          >
            <option value="admin">admin</option>
            <option value="analyst">analyst</option>
            <option value="viewer">viewer</option>
          </select>
          <Button type="submit" variant="primary">Create</Button>
        </div>
      </form>

      <div className="surface" style={{ padding: 16 }}>
        {users.map((u) => (
          <div key={u.id} className="list-row" style={{ alignItems: "center" }}>
            <strong>{u.username}</strong>
            <Badge>{u.role}</Badge>
            <span>{u.is_active ? "active" : "inactive"}</span>
            <span className="muted">last login {u.last_login || "—"}</span>
            <select
              className="field__select"
              value={u.role}
              onChange={async (e) => {
                setError("");
                try {
                  await updateUserRole(u.id, e.target.value);
                  await load();
                } catch (err) {
                  setError(apiMessage(err, "Role update failed."));
                }
              }}
            >
              <option value="admin">admin</option>
              <option value="analyst">analyst</option>
              <option value="viewer">viewer</option>
            </select>
            {u.is_active ? (
              <Button
                size="sm"
                variant="danger"
                onClick={async () => {
                  setError("");
                  try {
                    await deactivateUser(u.id);
                    await load();
                  } catch (err) {
                    setError(apiMessage(err, "Deactivate failed."));
                  }
                }}
              >
                Deactivate
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={async () => {
                  setError("");
                  try {
                    await activateUser(u.id);
                    await load();
                  } catch (err) {
                    setError(apiMessage(err, "Activate failed."));
                  }
                }}
              >
                Activate
              </Button>
            )}
            <Button size="sm" onClick={() => onResetPassword(u)}>
              Reset PW
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}

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

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
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
    load().catch(() => {});
  }, []);

  const onCreate = async (e) => {
    e.preventDefault();
    await createUser(form);
    setForm({ username: "", password: "", role: "analyst" });
    await load();
  };

  return (
    <div className="page-shell">
      <h1>User Management</h1>
      <p className="page-shell__copy">Admin-only account lifecycle controls with last-admin protection.</p>

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
                await updateUserRole(u.id, e.target.value);
                await load();
              }}
            >
              <option value="admin">admin</option>
              <option value="analyst">analyst</option>
              <option value="viewer">viewer</option>
            </select>
            {u.is_active ? (
              <Button size="sm" variant="danger" onClick={async () => { await deactivateUser(u.id); await load(); }}>
                Deactivate
              </Button>
            ) : (
              <Button size="sm" onClick={async () => { await activateUser(u.id); await load(); }}>
                Activate
              </Button>
            )}
            <Button
              size="sm"
              onClick={async () => {
                const password = window.prompt("New password (8+ chars)");
                if (!password) return;
                await resetUserPassword(u.id, password);
                window.alert("Password reset; sessions revoked.");
              }}
            >
              Reset PW
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}

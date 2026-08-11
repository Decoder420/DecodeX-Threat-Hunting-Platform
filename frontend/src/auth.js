/**
 * Central authorization helpers for the SOC UI.
 * Prefer these over scattering role string checks across components.
 */

const USER_KEY = "user";
const TOKEN_KEY = "token";

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

export function getStoredUser() {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setSession(token, user) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  }
  if (user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getPermissions(user = getStoredUser()) {
  if (!user) return [];
  if (Array.isArray(user.permissions) && user.permissions.length) {
    return user.permissions;
  }
  // Fallback if an older session lacks permissions (pre-Phase-1 tokens).
  return permissionsForRole(user.role);
}

export function permissionsForRole(role) {
  const map = {
    admin: [
      "users.read",
      "users.write",
      "roles.read",
      "roles.write",
      "alerts.read",
      "alerts.write",
      "events.read",
      "events.write",
      "rules.read",
      "rules.write",
      "yara.read",
      "yara.write",
      "sigma.read",
      "sigma.write",
      "feeds.read",
      "feeds.write",
      "suppressions.read",
      "suppressions.write",
      "cases.read",
      "cases.write",
      "ioc.read",
      "ioc.write",
      "assets.read",
      "assets.write",
      "webscan.read",
      "webscan.run",
      "soar.execute",
      "reports.read",
      "audit.read",
      "system.read",
      "system.write",
      "dashboard.read",
      "ingest_keys.read",
      "ingest_keys.write",
    ],
    analyst: [
      "alerts.read",
      "alerts.write",
      "events.read",
      "events.write",
      "rules.read",
      "yara.read",
      "sigma.read",
      "feeds.read",
      "suppressions.read",
      "suppressions.write",
      "cases.read",
      "cases.write",
      "ioc.read",
      "ioc.write",
      "assets.read",
      "webscan.read",
      "webscan.run",
      "soar.execute",
      "reports.read",
      "dashboard.read",
    ],
    viewer: [
      "alerts.read",
      "events.read",
      "ioc.read",
      "assets.read",
      "reports.read",
      "dashboard.read",
    ],
  };
  return map[role] || [];
}

export function hasPermission(permission, user = getStoredUser()) {
  if (!permission) return false;
  return getPermissions(user).includes(permission);
}

export function hasRole(role, user = getStoredUser()) {
  if (!user || !role) return false;
  return String(user.role).toLowerCase() === String(role).toLowerCase();
}

export function isAdmin(user = getStoredUser()) {
  return hasRole("admin", user);
}

export function canAccessAdminPanel(user = getStoredUser()) {
  return hasPermission("users.read", user) || hasPermission("yara.write", user);
}

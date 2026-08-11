import { hasPermission, hasRole } from "../auth";

/**
 * Conditionally render children when the current user has a permission.
 * Use for hiding destructive / admin-only controls (backend still enforces).
 */
export function PermissionGate({ permission, children, fallback = null }) {
  if (!hasPermission(permission)) {
    return fallback;
  }
  return children;
}

/**
 * Conditionally render children when the current user has one of the roles.
 */
export function RoleGate({ role, roles, children, fallback = null }) {
  const allowed = Array.isArray(roles) ? roles : role ? [role] : [];
  const ok = allowed.some((r) => hasRole(r));
  if (!ok) {
    return fallback;
  }
  return children;
}

export default PermissionGate;

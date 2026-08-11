import { Navigate } from "react-router-dom";
import { getStoredToken, hasPermission, hasRole } from "../auth";

export default function ProtectedRoute({
  children,
  permission,
  role,
  roles,
  fallback = "/dashboard",
}) {
  if (!getStoredToken()) {
    return <Navigate to="/login" replace />;
  }
  if (permission && !hasPermission(permission)) {
    return <Navigate to={fallback} replace />;
  }
  const allowedRoles = Array.isArray(roles) ? roles : role ? [role] : null;
  if (allowedRoles && !allowedRoles.some((r) => hasRole(r))) {
    return <Navigate to={fallback} replace />;
  }
  return children;
}

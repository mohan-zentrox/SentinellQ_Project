import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import type { Role } from "../api/types";

/**
 * Gate a route subtree on role.
 *
 * Purely to avoid rendering a page whose every request would 403 -- the backend's
 * `require_role` is the actual enforcement. Redirects rather than showing an
 * error, because arriving here means a stale link or a demotion, not an attack.
 */
export default function RoleRoute({ minimumRole }: { minimumRole: Role }) {
  const hasRole = useAuthStore((state) => state.hasRole);
  return hasRole(minimumRole) ? <Outlet /> : <Navigate to="/alerts" replace />;
}

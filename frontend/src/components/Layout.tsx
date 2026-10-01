import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuthStore } from "../store/authStore";
import type { Role } from "../api/types";

/** `minimumRole` hides a destination the API would refuse anyway. The server
 *  remains the authority; this is navigation hygiene, not access control. */
const navItems: { to: string; label: string; minimumRole?: Role }[] = [
  { to: "/alerts", label: "Alerts" },
  { to: "/cases", label: "Cases" },
  { to: "/events", label: "Telemetry" },
  { to: "/rules", label: "Rules" },
  { to: "/threat-intel", label: "Threat intel" },
  { to: "/playbooks", label: "Automation" },
  { to: "/reports", label: "Reports" },
  { to: "/users", label: "Users", minimumRole: "admin" },
  { to: "/settings", label: "Settings", minimumRole: "admin" },
  { to: "/billing", label: "Billing", minimumRole: "owner" },
];

export default function Layout() {
  const { role, refreshToken, logout, hasRole } = useAuthStore();
  const navigate = useNavigate();

  async function handleLogout() {
    // Tell the server, so the refresh token is actually revoked rather than
    // left valid until it expires. Local state is cleared either way.
    try {
      if (refreshToken) {
        await api.post("/auth/logout", { refreshToken });
      }
    } catch {
      // A failed logout call must not trap the user in a signed-in UI.
    } finally {
      logout();
      navigate("/login");
    }
  }

  const visibleItems = navItems.filter((item) => !item.minimumRole || hasRole(item.minimumRole));

  return (
    <div className="min-h-screen flex flex-col bg-slate-50">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="flex flex-wrap items-center gap-6">
            <span className="font-semibold text-brand-700">SentinelIQ</span>
            <nav className="flex flex-wrap gap-4">
              {visibleItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `text-sm font-medium ${isActive ? "text-brand-700" : "text-slate-500 hover:text-slate-800"}`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3 text-sm text-slate-500">
            {role && (
              <span className="rounded bg-slate-100 px-2 py-1 text-xs uppercase tracking-wide">{role}</span>
            )}
            <button onClick={handleLogout} className="text-slate-500 hover:text-slate-800">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}

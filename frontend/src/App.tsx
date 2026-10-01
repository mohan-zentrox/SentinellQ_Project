import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import RoleRoute from "./components/RoleRoute";
import Signup from "./pages/Signup/Signup";
import Login from "./pages/Login/Login";
import AlertsDashboard from "./pages/AlertsDashboard/AlertsDashboard";
import AlertDetail from "./pages/AlertDetail/AlertDetail";
import CasesList from "./pages/Cases/CasesList";
import CaseDetail from "./pages/CaseDetail/CaseDetail";
import Events from "./pages/Events/Events";
import Rules from "./pages/Rules/Rules";
import ThreatIntel from "./pages/ThreatIntel/ThreatIntel";
import Playbooks from "./pages/Playbooks/Playbooks";
import Reports from "./pages/Reports/Reports";
import Users from "./pages/Users/Users";
import Settings from "./pages/Settings/Settings";
import Billing from "./pages/Billing/Billing";
import NotFound from "./pages/NotFound/NotFound";

export default function App() {
  return (
    <Routes>
      <Route path="/signup" element={<Signup />} />
      <Route path="/login" element={<Login />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/alerts" element={<AlertsDashboard />} />
          <Route path="/alerts/:alertId" element={<AlertDetail />} />
          <Route path="/cases" element={<CasesList />} />
          <Route path="/cases/:caseId" element={<CaseDetail />} />
          <Route path="/events" element={<Events />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/playbooks" element={<Playbooks />} />
          <Route path="/reports" element={<Reports />} />

          {/* Role-gated areas. The API enforces these too; routing them here
              avoids rendering a page that can only produce 403s. */}
          <Route element={<RoleRoute minimumRole="admin" />}>
            <Route path="/users" element={<Users />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
          <Route element={<RoleRoute minimumRole="owner" />}>
            <Route path="/billing" element={<Billing />} />
          </Route>

          {/* An unknown path inside the app shell gets a real 404 page rather
              than a silent redirect that makes a typo look like a working link. */}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>

      <Route path="/" element={<Navigate to="/alerts" replace />} />
    </Routes>
  );
}

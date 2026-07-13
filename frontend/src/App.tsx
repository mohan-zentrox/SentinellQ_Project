import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import Signup from "./pages/Signup/Signup";
import Login from "./pages/Login/Login";
import AlertsDashboard from "./pages/AlertsDashboard/AlertsDashboard";
import CaseDetail from "./pages/CaseDetail/CaseDetail";
import Billing from "./pages/Billing/Billing";

export default function App() {
  return (
    <Routes>
      <Route path="/signup" element={<Signup />} />
      <Route path="/login" element={<Login />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/alerts" element={<AlertsDashboard />} />
          <Route path="/cases/:caseId" element={<CaseDetail />} />
          <Route path="/billing" element={<Billing />} />
        </Route>
      </Route>

      <Route path="/" element={<Navigate to="/alerts" replace />} />
      <Route path="*" element={<Navigate to="/alerts" replace />} />
    </Routes>
  );
}

import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router-dom";
import RoleRoute from "./RoleRoute";
import ProtectedRoute from "./ProtectedRoute";
import { renderWithRouter, signIn } from "../test/helpers";

function Guarded() {
  return (
    <Routes>
      <Route path="/alerts" element={<p>Alerts page</p>} />
      <Route element={<RoleRoute minimumRole="admin" />}>
        <Route path="/settings" element={<p>Settings page</p>} />
      </Route>
    </Routes>
  );
}

describe("RoleRoute", () => {
  it("renders the route for a sufficiently privileged role", async () => {
    signIn("admin");
    await renderWithRouter(<Guarded />, { route: "/settings" });
    expect(screen.getByText("Settings page")).toBeInTheDocument();
  });

  it("accepts a more privileged role, matching the ordered backend hierarchy", async () => {
    signIn("owner");
    await renderWithRouter(<Guarded />, { route: "/settings" });
    expect(screen.getByText("Settings page")).toBeInTheDocument();
  });

  it("redirects an under-privileged role instead of rendering a page of 403s", async () => {
    signIn("analyst");
    await renderWithRouter(<Guarded />, { route: "/settings" });
    expect(screen.queryByText("Settings page")).not.toBeInTheDocument();
    expect(screen.getByText("Alerts page")).toBeInTheDocument();
  });
});

describe("ProtectedRoute", () => {
  function Shell() {
    return (
      <Routes>
        <Route path="/login" element={<p>Login page</p>} />
        <Route element={<ProtectedRoute />}>
          <Route path="/alerts" element={<p>Alerts page</p>} />
        </Route>
      </Routes>
    );
  }

  it("sends an unauthenticated visitor to login", async () => {
    await renderWithRouter(<Shell />, { route: "/alerts" });
    expect(screen.getByText("Login page")).toBeInTheDocument();
  });

  it("lets an authenticated visitor through", async () => {
    signIn("viewer");
    await renderWithRouter(<Shell />, { route: "/alerts" });
    expect(screen.getByText("Alerts page")).toBeInTheDocument();
  });
});

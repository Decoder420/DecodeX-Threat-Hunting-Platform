import { render, screen } from "@testing-library/react";
import { permissionsForRole, hasPermission, setSession, clearSession } from "./auth";

// Full App pulls react-router ESM that CRA Jest may not resolve; cover login
// contract via auth helpers + a lightweight form smoke elsewhere.
test("viewer permissions are read-only", () => {
  clearSession();
  const perms = permissionsForRole("viewer");
  expect(perms).toContain("dashboard.read");
  expect(perms).not.toContain("soar.execute");
  setSession("t", { role: "viewer", permissions: perms });
  expect(hasPermission("alerts.write")).toBe(false);
  expect(hasPermission("alerts.read")).toBe(true);
});

test("admin permissions include user management", () => {
  const perms = permissionsForRole("admin");
  expect(perms).toContain("users.write");
  expect(perms).toContain("audit.read");
  expect(perms).toContain("webscan.run");
});

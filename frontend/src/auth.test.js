import {
  clearSession,
  getPermissions,
  hasPermission,
  hasRole,
  permissionsForRole,
  setSession,
} from "./auth";

describe("auth helpers", () => {
  beforeEach(() => {
    clearSession();
  });

  test("permissionsForRole returns expected viewer set", () => {
    const perms = permissionsForRole("viewer");
    expect(perms).toContain("dashboard.read");
    expect(perms).not.toContain("soar.execute");
    expect(perms).not.toContain("users.write");
  });

  test("hasPermission uses stored user permissions", () => {
    setSession("tok", {
      id: 1,
      username: "analyst",
      role: "analyst",
      permissions: ["alerts.write", "dashboard.read"],
    });
    expect(hasPermission("alerts.write")).toBe(true);
    expect(hasPermission("users.write")).toBe(false);
  });

  test("hasRole checks role string", () => {
    setSession("tok", { id: 2, username: "admin", role: "admin", permissions: [] });
    expect(hasRole("admin")).toBe(true);
    expect(hasRole("viewer")).toBe(false);
  });

  test("getPermissions falls back to role map", () => {
    setSession("tok", { id: 3, username: "v", role: "viewer" });
    expect(getPermissions()).toContain("alerts.read");
  });
});

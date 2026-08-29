import React from "react";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import SettingsPage from "./SettingsPage";
import api from "../api";

jest.mock("../api");

test("renders settings page with organization branding and integrations", async () => {
  api.get.mockImplementation((url) => {
    if (url === "/settings") {
      return Promise.resolve({
        data: {
          company_name: "DecodeX Security Technologies Private Limited",
          tagline: "Enterprise Threat Hunting & Modern Cloud SIEM",
          timezone: "UTC",
          contact_email: "soc@decodex.internal",
          ai_provider: "builtin",
          retention_days: 90,
          compliance_mode: true,
        },
      });
    }
    if (url === "/admin/ingest_keys") {
      return Promise.resolve({
        data: {
          keys: [
            {
              id: 1,
              name: "Vercel Prod",
              source: "vercel",
              key_preview: "thk_abc...",
              is_active: true,
              created_at: new Date().toISOString(),
            },
          ],
        },
      });
    }
    return Promise.resolve({ data: {} });
  });

  render(
    <MemoryRouter>
      <SettingsPage />
    </MemoryRouter>
  );

  expect(await screen.findByText(/Platform Settings & Integrations/i)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Organization Branding/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Integrations Hub/i })).toBeInTheDocument();
});

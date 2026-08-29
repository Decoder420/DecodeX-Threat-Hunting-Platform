import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import CommandPalette from "./CommandPalette";
import api from "../api";

jest.mock("../api");

test("renders command palette when open and filters items by search query", async () => {
  api.get.mockImplementation((url) => {
    if (url === "/web-targets") {
      return Promise.resolve({ data: { targets: [{ id: 1, name: "IUIS", url: "https://iuis.in" }] } });
    }
    if (url.startsWith("/alerts")) {
      return Promise.resolve({ data: { alerts: [{ id: 101, title: "SQLi Detected", severity: "CRITICAL" }] } });
    }
    return Promise.resolve({ data: {} });
  });

  render(
    <MemoryRouter>
      <CommandPalette isOpen={true} onClose={() => {}} onOpenProwler={() => {}} />
    </MemoryRouter>
  );

  expect(screen.getByPlaceholderText(/Type a command/i)).toBeInTheDocument();
  expect(screen.getByText(/Executive SOC Dashboard/i)).toBeInTheDocument();

  // Test searching
  const input = screen.getByPlaceholderText(/Type a command/i);
  fireEvent.change(input, { target: { value: "Prowler" } });

  expect(screen.getByText(/Open Prowler Cloud Security Posture/i)).toBeInTheDocument();
});

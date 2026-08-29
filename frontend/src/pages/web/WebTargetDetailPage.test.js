import React from "react";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import WebTargetDetailPage from "./WebTargetDetailPage";
import api from "../../api";

jest.mock("../../api");
jest.mock("../../webApi");

const mockCockpit = {
  target: {
    id: 1,
    name: "Production Web Portal",
    url: "https://portal.example.com",
    authorization_status: "AUTHORIZED",
    risk_score: 65,
    environment: "production",
  },
  findings: [
    {
      id: 101,
      title: "SQL Injection in Search",
      severity: "HIGH",
      url: "/search?q=1",
      param: "q",
      method: "GET",
      solution: "Use parameterized queries",
    },
  ],
  scans: [],
  attack_surface: [],
  correlated_alerts: [],
};

test("renders target investigation cockpit with target name and risk", async () => {
  api.get.mockResolvedValueOnce({ data: mockCockpit });

  render(
    <MemoryRouter initialEntries={["/webscan/targets/1"]}>
      <Routes>
        <Route path="/webscan/targets/:targetId" element={<WebTargetDetailPage />} />
      </Routes>
    </MemoryRouter>
  );

  const targets = await screen.findAllByText(/Production Web Portal/i);
  expect(targets.length).toBeGreaterThan(0);
  expect(screen.getByText(/Dedicated Target Investigation Cockpit/i)).toBeInTheDocument();
  expect(screen.getByText(/SQL Injection in Search/i)).toBeInTheDocument();
});

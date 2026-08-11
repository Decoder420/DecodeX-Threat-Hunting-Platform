import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import webApi from "../../webApi";
import WebOverviewPage from "./WebOverviewPage";

jest.mock("../../webApi", () => ({
  __esModule: true,
  default: {
    getOverview: jest.fn(),
  },
}));

beforeEach(() => {
  webApi.getOverview.mockResolvedValue({
    data: {
      totals: {
        targets: 2,
        authorized_targets: 1,
        active_scans: 0,
        completed_scans: 1,
        critical_findings: 0,
        high_findings: 1,
        avg_risk_score: 40,
      },
      findings_by_severity: { HIGH: 1 },
      findings_by_category: { headers: 1 },
      engines: { builtin: { status: "READY" } },
    },
  });
});

test("renders web security overview KPIs", async () => {
  render(
    <MemoryRouter>
      <WebOverviewPage />
    </MemoryRouter>
  );
  await waitFor(() => {
    expect(screen.getByText("Authorized")).toBeInTheDocument();
  });
  expect(screen.getByText("Engine readiness")).toBeInTheDocument();
});

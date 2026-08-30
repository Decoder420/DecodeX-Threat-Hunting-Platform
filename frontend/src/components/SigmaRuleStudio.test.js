import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import SigmaRuleStudio from "./SigmaRuleStudio";
import MitreAttackMatrix from "./MitreAttackMatrix";
import * as api from "../api";

jest.mock("../api", () => ({
  validateSigmaRule: jest.fn(),
  testSigmaRule: jest.fn(),
  saveSigmaRule: jest.fn(),
  getMitreMatrix: jest.fn(),
}));

jest.mock("../auth", () => ({
  hasPermission: () => true,
}));

describe("SigmaRuleStudio", () => {
  it("renders editor header and preset templates", () => {
    render(<SigmaRuleStudio />);
    expect(screen.getByText(/Sigma Rule Studio & Live Tester/i)).toBeInTheDocument();
    expect(screen.getByText(/✓ Validate Schema/i)).toBeInTheDocument();
    expect(screen.getByText(/🚀 Deploy Rule/i)).toBeInTheDocument();
  });

  it("handles rule validation click and displays success", async () => {
    api.validateSigmaRule.mockResolvedValueOnce({
      data: {
        valid: true,
        format: "sigma",
        rule_count: 1,
        rules: [{ id: "test_rule", severity: "high", technique_id: "T1059.001" }],
      },
    });

    render(<SigmaRuleStudio />);
    const validateBtn = screen.getByText(/✓ Validate Schema/i);
    fireEvent.click(validateBtn);

    await waitFor(() => {
      expect(screen.getByText(/Valid Rule/i)).toBeInTheDocument();
      expect(screen.getAllByText(/T1059.001/i).length).toBeGreaterThan(0);
    });
  });

  it("handles live dry run testing and displays match status", async () => {
    api.testSigmaRule.mockResolvedValueOnce({
      data: {
        status: "ok",
        matched: true,
        match_count: 1,
        evaluated_events_count: 1,
        execution_time_ms: 1.15,
        matches: [
          {
            rule_id: "sigma_test_curl",
            severity: "high",
            description: "Suspicious curl detected",
            matched_event: { process: "curl", commandline: "curl http://evil.com" },
          },
        ],
      },
    });

    render(<SigmaRuleStudio />);
    const testBtn = screen.getByText(/⚡ Run Live Dry-Run Test/i);
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(screen.getByText(/🚨 MATCH DETECTED/i)).toBeInTheDocument();
      expect(screen.getByText(/1.15 ms/i)).toBeInTheDocument();
    });
  });
});

describe("MitreAttackMatrix", () => {
  it("renders matrix with KPI summary", async () => {
    api.getMitreMatrix.mockResolvedValueOnce({
      data: {
        status: "ok",
        summary: {
          total_tactics: 12,
          covered_tactics: 7,
          total_techniques: 44,
          covered_techniques: 11,
          coverage_percentage: 25.0,
          active_rules_count: 12,
        },
        tactics: [
          {
            tactic_id: "TA0002",
            tactic_name: "Execution",
            covered: true,
            techniques: [
              {
                id: "T1059.001",
                name: "Command & Scripting: PowerShell",
                covered: true,
                rule_count: 3,
                rules: [{ id: "advanced_powershell_attack", description: "PowerShell attack", severity: "high" }],
              },
            ],
          },
        ],
      },
    });

    render(<MitreAttackMatrix onSelectTechniqueForStudio={() => {}} />);
    await waitFor(() => {
      expect(screen.getByText(/MITRE ATT&CK Enterprise Coverage Matrix/i)).toBeInTheDocument();
      expect(screen.getByText(/7 \/ 12/i)).toBeInTheDocument();
      expect(screen.getByText(/T1059.001/i)).toBeInTheDocument();
    });
  });
});

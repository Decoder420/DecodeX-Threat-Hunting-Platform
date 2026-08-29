import React from "react";
import { render, screen } from "@testing-library/react";
import ProwlerSidePanel from "./ProwlerSidePanel";
import api from "../api";

jest.mock("../api");

test("renders Prowler side panel when open with compliance score", async () => {
  api.get.mockResolvedValueOnce({
    data: {
      score: 85,
      passed: 6,
      failed: 2,
      warn: 0,
      total: 8,
      checks: [
        {
          id: "prowler_iam_01",
          code: "CIS-1.1",
          standard: "CIS AWS Benchmark v3.0",
          service: "IAM",
          title: "Ensure MFA is enabled for root account",
          status: "PASS",
          severity: "CRITICAL",
          resource: "arn:aws:iam::root",
          remediation: "aws iam create-virtual-mfa-device...",
          rationale: "Prevent unauthorized takeover.",
        },
      ],
    },
  });

  render(<ProwlerSidePanel isOpen={true} onClose={() => {}} />);

  expect(await screen.findByText(/Prowler Cloud Posture & Compliance/i)).toBeInTheDocument();
  expect(await screen.findByText(/85%/i)).toBeInTheDocument();
  expect(await screen.findByText(/Ensure MFA is enabled for root account/i)).toBeInTheDocument();
  expect(screen.getByText(/Run Prowler Audit/i)).toBeInTheDocument();
});

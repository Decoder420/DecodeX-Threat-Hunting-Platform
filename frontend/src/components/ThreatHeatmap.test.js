import React from "react";
import { render, screen } from "@testing-library/react";
import ThreatHeatmap from "./ThreatHeatmap";

test("renders ThreatHeatmap with days of week and legend", () => {
  render(<ThreatHeatmap alerts={[]} />);

  expect(screen.getByText(/7-Day Threat Frequency & Ingress Velocity Heatmap/i)).toBeInTheDocument();
  expect(screen.getByText("Mon")).toBeInTheDocument();
  expect(screen.getByText("Fri")).toBeInTheDocument();
  expect(screen.getByText(/Critical Spike/i)).toBeInTheDocument();
});

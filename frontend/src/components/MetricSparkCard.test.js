import React from "react";
import { render, screen } from "@testing-library/react";
import MetricSparkCard from "./MetricSparkCard";

test("renders MetricSparkCard with value, delta, and icon", () => {
  render(
    <MetricSparkCard
      title="Total Alerts"
      value="42"
      delta="+14.2%"
      isPositiveDelta={true}
      hint="Past 24 hours"
      icon="🚨"
      sparklineData={[5, 10, 15, 20, 25, 30]}
    />
  );

  expect(screen.getByText("Total Alerts")).toBeInTheDocument();
  expect(screen.getByText("42")).toBeInTheDocument();
  expect(screen.getByText(/14.2%/)).toBeInTheDocument();
  expect(screen.getByText("Past 24 hours")).toBeInTheDocument();
});

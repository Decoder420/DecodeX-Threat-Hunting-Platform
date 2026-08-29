import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import LiveTelemetryTicker from "./LiveTelemetryTicker";

test("renders LiveTelemetryTicker collapsed and expands on click", () => {
  render(<LiveTelemetryTicker />);

  expect(screen.getByText(/Live Telemetry Stream/i)).toBeInTheDocument();
  expect(screen.getByText(/Expand Stream HUD/i)).toBeInTheDocument();

  // Click to expand HUD
  fireEvent.click(screen.getByText(/Live Telemetry Stream/i));

  expect(screen.getByText(/Collapse HUD/i)).toBeInTheDocument();
  expect(screen.getByText(/Pause/i)).toBeInTheDocument();
});

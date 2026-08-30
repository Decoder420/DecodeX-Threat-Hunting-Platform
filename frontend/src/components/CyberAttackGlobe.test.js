import React from "react";
import { render, screen } from "@testing-library/react";
import CyberAttackGlobe from "./CyberAttackGlobe";

beforeAll(() => {
  HTMLCanvasElement.prototype.getContext = () => ({
    clearRect: () => {},
    beginPath: () => {},
    arc: () => {},
    fill: () => {},
    stroke: () => {},
    moveTo: () => {},
    lineTo: () => {},
    quadraticCurveTo: () => {},
    createRadialGradient: () => ({ addColorStop: () => {} }),
    createLinearGradient: () => ({ addColorStop: () => {} }),
    setLineDash: () => {},
    fillRect: () => {},
    save: () => {},
    restore: () => {},
    clip: () => {},
  });
  window.requestAnimationFrame = (cb) => setTimeout(cb, 16);
  window.cancelAnimationFrame = (id) => clearTimeout(id);
});

test("renders CyberAttackGlobe with clean empty state when no alerts provided", () => {
  render(<CyberAttackGlobe alerts={[]} />);

  expect(screen.getByText(/Global Threat Actor Radar/i)).toBeInTheDocument();
  expect(screen.getByText(/Inbound Intercept Queue/i)).toBeInTheDocument();
  expect(screen.getByText(/0 Active Vectors/i)).toBeInTheDocument();
  expect(screen.getByText(/No Active External Threat Vectors/i)).toBeInTheDocument();
});

test("renders CyberAttackGlobe with dynamic attack vector from alerts", () => {
  const sampleAlerts = [
    {
      id: "alt-1",
      ip: "198.51.100.42",
      tactic: "SQL Injection Probe",
      technique_id: "T1190",
      severity: "CRITICAL",
      host: "api.target.com",
    },
  ];
  render(<CyberAttackGlobe alerts={sampleAlerts} />);

  expect(screen.getByText(/1 Active Vector/i)).toBeInTheDocument();
  expect(screen.getByText(/198.51.100.42/i)).toBeInTheDocument();
});

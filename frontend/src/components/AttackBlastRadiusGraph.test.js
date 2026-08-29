import React from "react";
import { render, screen } from "@testing-library/react";
import AttackBlastRadiusGraph from "./AttackBlastRadiusGraph";

beforeAll(() => {
  HTMLCanvasElement.prototype.getContext = () => ({
    clearRect: () => {},
    beginPath: () => {},
    arc: () => {},
    fill: () => {},
    stroke: () => {},
    moveTo: () => {},
    lineTo: () => {},
    fillRect: () => {},
    fillText: () => {},
    createLinearGradient: () => ({ addColorStop: () => {} }),
    setLineDash: () => {},
  });
  window.requestAnimationFrame = (cb) => setTimeout(cb, 16);
  window.cancelAnimationFrame = (id) => clearTimeout(id);
});

test("renders AttackBlastRadiusGraph with target node and details drawer", () => {
  const target = { id: 1, name: "IUIS Production", url: "https://iuis.in" };
  const findings = [{ id: 10, title: "SQL Injection", severity: "CRITICAL", path: "/api/login" }];
  const alerts = [];

  render(<AttackBlastRadiusGraph target={target} findings={findings} alerts={alerts} />);

  expect(screen.getByText(/Attack Blast Radius & Infrastructure Node Graph/i)).toBeInTheDocument();
  expect(screen.getByText(/Live Topology/i)).toBeInTheDocument();
  expect(screen.getByText(/IUIS Production/i)).toBeInTheDocument();
});

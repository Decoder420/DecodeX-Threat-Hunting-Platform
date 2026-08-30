import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import WebhookManagerModal from "./WebhookManagerModal";
import * as api from "../api";

jest.mock("../api", () => ({
  listWebhooks: jest.fn(),
  createWebhook: jest.fn(),
  deleteWebhook: jest.fn(),
  testWebhook: jest.fn(),
}));

jest.mock("../auth", () => ({
  hasPermission: () => true,
}));

describe("WebhookManagerModal Component", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("does not render when isOpen is false", () => {
    render(<WebhookManagerModal isOpen={false} onClose={() => {}} />);
    expect(screen.queryByText(/Webhook Alert Channels/i)).not.toBeInTheDocument();
  });

  test("loads and renders active webhooks when open", async () => {
    api.listWebhooks.mockResolvedValueOnce({
      data: {
        webhooks: [
          {
            id: 1,
            name: "SOC Discord Channel",
            url: "https://discord.com/api/webhooks/123/xyz",
            channel_type: "discord",
            events_subscribed: "alert.critical,finding.critical",
            is_active: true,
            delivery_count: 5,
          },
        ],
      },
    });

    render(<WebhookManagerModal isOpen={true} onClose={() => {}} />);

    expect(screen.getByText(/Webhook Alert Channels/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("SOC Discord Channel")).toBeInTheDocument();
      expect(screen.getByText("💬 Discord")).toBeInTheDocument();
      expect(screen.getByText(/⚡ Test Ping/i)).toBeInTheDocument();
    });
  });

  test("triggers test ping and displays success response", async () => {
    api.listWebhooks.mockResolvedValueOnce({
      data: {
        webhooks: [
          {
            id: 1,
            name: "Slack Critical Alerts",
            url: "https://hooks.slack.com/services/T0/B0/X0",
            channel_type: "slack",
            events_subscribed: "alert.critical",
            is_active: true,
            delivery_count: 2,
          },
        ],
      },
    });

    api.testWebhook.mockResolvedValueOnce({
      data: {
        delivered: true,
        http_status: 200,
        response: "ok",
      },
    });

    render(<WebhookManagerModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(screen.getByText("Slack Critical Alerts")).toBeInTheDocument();
    });

    const testBtn = screen.getByText(/⚡ Test Ping/i);
    fireEvent.click(testBtn);

    await waitFor(() => {
      expect(api.testWebhook).toHaveBeenCalledWith(1);
      expect(screen.getByText(/Test Ping Delivered Successfully/i)).toBeInTheDocument();
    });
  });
});

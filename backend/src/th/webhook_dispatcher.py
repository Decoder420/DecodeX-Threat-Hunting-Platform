"""
DecodeX Webhook Dispatcher Engine
=================================
Provides secure, asynchronous real-time incident alerting to:
- Discord (Rich Color Embeds)
- Slack (Block Kit Cards)
- Microsoft Teams (MessageCards)
- Generic HTTP Webhook endpoints

Includes SSRF protection, timeout controls, and non-blocking background dispatch.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

import requests

from . import db as dbmod

logger = logging.getLogger("th.webhooks")

# Thread pool for asynchronous, non-blocking webhook delivery
_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="decodex_webhook_worker")

# Private and non-routable IP ranges for SSRF mitigation
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_ssrf_safe_url(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """
    Validates that a webhook URL is well-formed and does not target internal / loopback infrastructure.
    """
    if allow_private or os.environ.get("ALLOW_PRIVATE_WEBHOOKS", "").lower() in ("true", "1", "yes"):
        return True, ""

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "URL scheme must be http or https."

        hostname = parsed.hostname
        if not hostname:
            return False, "Missing hostname in webhook URL."

        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
            return False, "Destination points to a loopback or cloud metadata address."

        # Resolve IP to detect SSRF to private LAN
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_str = item[4][0]
                ip_obj = ipaddress.ip_address(ip_str)
                for net in _PRIVATE_NETWORKS:
                    if ip_obj in net:
                        return False, f"Destination resolves to a protected private address ({ip_str})."
        except socket.gaierror:
            # If DNS fails at validation time, allow for now unless unreachable
            pass

        return True, ""
    except Exception as exc:
        return False, f"Malformed URL: {exc}"


# --- Channel Formatters ---

def format_discord_payload(severity: str, title: str, description: str, source: str, event_type: str, details: dict = None) -> dict:
    sev_upper = (severity or "INFO").upper()
    color = 0xFF2D55 if sev_upper == "CRITICAL" else 0xFF9500 if sev_upper == "HIGH" else 0xFFCC00 if sev_upper == "MEDIUM" else 0x34C759

    fields = [
        {"name": "Severity", "value": sev_upper, "inline": True},
        {"name": "Source / Target", "value": source or "DecodeX SIEM", "inline": True},
        {"name": "Event Type", "value": event_type, "inline": True},
    ]
    if details:
        for k, v in list(details.items())[:3]:
            if v and isinstance(v, (str, int, float)):
                fields.append({"name": str(k).replace("_", " ").title(), "value": str(v)[:200], "inline": True})

    return {
        "username": "DecodeX SOC & DAST",
        "avatar_url": "https://raw.githubusercontent.com/Decoder420/DecodeX-Threat-Hunting-Platform/main/docs/screenshots/dashboard.png",
        "embeds": [
            {
                "title": f"🚨 [{sev_upper}] {title}"[:256],
                "description": (description or "No description provided.")[:2048],
                "color": color,
                "fields": fields,
                "footer": {"text": "DecodeX Security Operations Center"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }


def format_slack_payload(severity: str, title: str, description: str, source: str, event_type: str, details: dict = None) -> dict:
    sev_upper = (severity or "INFO").upper()
    icon = "🔴" if sev_upper == "CRITICAL" else "🟠" if sev_upper == "HIGH" else "🟡" if sev_upper == "MEDIUM" else "🔵"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{icon} [{sev_upper}] {title}"[:150]},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": (description or "No description provided.")[:2000]},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*Target/Host:* `{source}`  |  *Event:* `{event_type}`  |  *Time:* `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
                }
            ],
        },
    ]

    return {
        "text": f"🚨 [{sev_upper}] {title}: {description}",
        "blocks": blocks,
    }


def format_teams_payload(severity: str, title: str, description: str, source: str, event_type: str, details: dict = None) -> dict:
    sev_upper = (severity or "INFO").upper()
    theme_color = "FF0000" if sev_upper == "CRITICAL" else "FFA500" if sev_upper == "HIGH" else "FFCC00" if sev_upper == "MEDIUM" else "0078D7"

    facts = [
        {"name": "Severity", "value": sev_upper},
        {"name": "Target / Host", "value": source or "DecodeX"},
        {"name": "Event Type", "value": event_type},
        {"name": "Timestamp", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")},
    ]
    if details:
        for k, v in list(details.items())[:3]:
            if v and isinstance(v, (str, int, float)):
                facts.append({"name": str(k).replace("_", " ").title(), "value": str(v)[:100]})

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"[{sev_upper}] {title}",
        "sections": [
            {
                "activityTitle": f"🚨 [{sev_upper}] {title}",
                "activitySubtitle": "DecodeX Incident Alert",
                "text": description,
                "facts": facts,
            }
        ],
    }


def format_generic_payload(severity: str, title: str, description: str, source: str, event_type: str, details: dict = None) -> dict:
    return {
        "platform": "DecodeX",
        "event_type": event_type,
        "severity": (severity or "INFO").upper(),
        "title": title,
        "description": description,
        "source": source,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _send_single_webhook(webhook_id: int, url: str, channel_type: str, payload_data: dict) -> None:
    """Executes HTTP POST delivery to a single webhook endpoint."""
    status_code = None
    last_error = ""

    # Format according to channel
    if channel_type == "discord":
        body = format_discord_payload(**payload_data)
    elif channel_type == "slack":
        body = format_slack_payload(**payload_data)
    elif channel_type == "teams":
        body = format_teams_payload(**payload_data)
    else:
        body = format_generic_payload(**payload_data)

    try:
        resp = requests.post(
            url,
            json=body,
            headers={"Content-Type": "application/json", "User-Agent": "DecodeX-Webhook-Dispatcher/2.2.0"},
            timeout=5.0,
        )
        status_code = resp.status_code
        if not resp.ok:
            last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:
        last_error = str(exc)
        logger.warning("Webhook dispatch to %s failed: %s", url, exc)

    # Record delivery metrics in database
    try:
        db = dbmod.SessionLocal()
        wh = db.query(dbmod.NotificationWebhook).filter_by(id=webhook_id).first()
        if wh:
            wh.last_triggered_at = dbmod.utcnow()
            wh.last_status_code = status_code
            wh.last_error = last_error
            wh.delivery_count = (wh.delivery_count or 0) + (1 if status_code and 200 <= status_code < 300 else 0)
            db.commit()
        db.close()
    except Exception as exc:
        logger.debug("Failed updating webhook status in db: %s", exc)


def dispatch_webhook_event(
    event_type: str,
    severity: str,
    title: str,
    description: str,
    source: str = "",
    details: dict = None,
) -> None:
    """
    Asynchronously evaluates and dispatches an event to all matching active webhooks.
    Event types: 'alert.critical', 'alert.high', 'finding.critical', 'finding.high', 'scan.completed', etc.
    """
    try:
        db = dbmod.SessionLocal()
        webhooks = db.query(dbmod.NotificationWebhook).filter_by(is_active=True).all()
        active_list = [(w.id, w.url, w.channel_type, w.events_subscribed) for w in webhooks]
        db.close()
    except Exception as exc:
        logger.debug("Unable to read webhooks: %s", exc)
        return

    payload_data = {
        "severity": severity,
        "title": title,
        "description": description,
        "source": source,
        "event_type": event_type,
        "details": details or {},
    }

    for wh_id, wh_url, ch_type, events_sub in active_list:
        sub_list = [e.strip().lower() for e in (events_sub or "").split(",") if e.strip()]
        
        # Check event match: wildcard "*", exact event_type, or prefix match (e.g. "alert.*")
        matched = (
            "*" in sub_list
            or event_type.lower() in sub_list
            or f"alert.{severity.lower()}" in sub_list
            or f"finding.{severity.lower()}" in sub_list
        )

        if matched:
            _executor.submit(_send_single_webhook, wh_id, wh_url, ch_type, payload_data)


def send_test_webhook_ping(webhook: NotificationWebhook) -> tuple[bool, int, str]:
    """Sends a synchronous test notification ping and returns (success, status_code, message)."""
    payload_data = {
        "severity": "INFO",
        "title": "DecodeX Webhook Test Ping",
        "description": f"This is a verified test alert sent from the DecodeX Threat Hunting & DAST Platform to channel '{webhook.name}'.",
        "source": "DecodeX-Core-Engine",
        "event_type": "webhook.test_ping",
        "details": {"channel": webhook.channel_type, "status": "verified"},
    }

    if webhook.channel_type == "discord":
        body = format_discord_payload(**payload_data)
    elif webhook.channel_type == "slack":
        body = format_slack_payload(**payload_data)
    elif webhook.channel_type == "teams":
        body = format_teams_payload(**payload_data)
    else:
        body = format_generic_payload(**payload_data)

    try:
        resp = requests.post(
            webhook.url,
            json=body,
            headers={"Content-Type": "application/json", "User-Agent": "DecodeX-Webhook-Dispatcher/2.2.0"},
            timeout=5.0,
        )
        return resp.ok, resp.status_code, resp.text[:300]
    except Exception as exc:
        return False, 0, str(exc)

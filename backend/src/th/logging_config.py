"""
Structured logging configuration with automated sensitive field redaction.
Formats log records as structured JSON (or consistent key=value) and masks secrets
(passwords, authorization tokens, API keys) even at DEBUG level.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

# Sensitive pattern regexes for automatic redaction in log messages
SENSITIVE_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~+/]+=*", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(X-ZAP-API-Key['\":\s=]+)[A-Za-z0-9_\-]+", re.IGNORECASE), r"\1[REDACTED_KEY]"),
    (re.compile(r"(apikey['\":\s=]+)[A-Za-z0-9_\-]+", re.IGNORECASE), r"\1[REDACTED_KEY]"),
    (re.compile(r"(password['\":\s=]+)[^\"',\s&]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(token['\":\s=]+)[A-Za-z0-9\-\._~+/]{8,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(secret['\":\s=]+)[^\"',\s&]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
]


def redact_sensitive_text(text: str) -> str:
    """Mask credentials, tokens, and keys from log string."""
    if not text or not isinstance(text, str):
        return text
    redacted = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class RedactingFilter(logging.Filter):
    """Logging filter that sanitizes secrets from log record messages and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_sensitive_text(str(v)) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(redact_sensitive_text(str(a)) if isinstance(a, str) else a for a in record.args)
        return True


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as machine-readable JSON with ISO-8601 UTC timestamps."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive_text(message),
            "source": f"{record.module}:{record.lineno}",
        }
        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)
        return json.dumps(data)


def configure_structured_logging(log_level: str | None = None, json_format: bool | None = None) -> None:
    """Initialize structured logging across backend runtime."""
    level_name = (log_level or os.environ.get("LOG_LEVEL", "INFO")).upper()
    use_json = json_format if json_format is not None else os.environ.get("LOG_FORMAT", "json").lower() == "json"
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Clear existing handlers to prevent duplicate lines
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(RedactingFilter())

    if use_json:
        handler.setFormatter(StructuredJsonFormatter())
    else:
        fmt = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        handler.setFormatter(logging.Formatter(fmt))

    root.addHandler(handler)

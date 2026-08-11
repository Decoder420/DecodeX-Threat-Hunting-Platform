"""Append-only application audit logging."""

from __future__ import annotations

from flask import has_request_context, request

from .db import AuditLog, utcnow


def write_audit(
    db,
    *,
    action: str,
    user=None,
    username: str = "",
    resource_type: str = "",
    resource_id: str = "",
    details: str = "",
    success: bool = True,
    source_ip: str | None = None,
) -> AuditLog:
    if source_ip is None and has_request_context():
        source_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    entry = AuditLog(
        timestamp=utcnow(),
        user_id=getattr(user, "id", None),
        username=getattr(user, "username", None) or username or "",
        action=action,
        resource_type=resource_type or "",
        resource_id=str(resource_id or ""),
        source_ip=source_ip or "",
        details=details or "",
        success=bool(success),
    )
    db.add(entry)
    db.commit()
    return entry

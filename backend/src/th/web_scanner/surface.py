"""Attack-surface tree helpers — path-based URL node construction (simplified)."""

from __future__ import annotations

import json
import logging
from typing import Callable
from urllib.parse import urlparse

from ..db import WebScan, WebScanEvent, WebScanNode, utcnow
from .config import max_severity

logger = logging.getLogger("th.web_scanner.surface")


def _serialize_node(node: WebScanNode) -> dict:
    return {
        "id": node.id,
        "scan_id": node.scan_id,
        "target_id": node.target_id,
        "parent_id": node.parent_id,
        "node_key": node.node_key,
        "node_type": node.node_type,
        "label": node.label,
        "url": node.url,
        "hostname": node.hostname,
        "ip": node.ip,
        "port": node.port,
        "protocol": node.protocol,
        "http_status": node.http_status,
        "title": node.title,
        "technology": node.technology,
        "depth": node.depth,
        "severity": node.severity,
        "descendant_severity": node.descendant_severity,
        "finding_count": node.finding_count,
        "descendant_finding_count": node.descendant_finding_count,
        "has_alert": bool(node.has_alert),
        "risk_score": node.risk_score,
        "discovered_at": node.discovered_at.isoformat() if node.discovered_at else None,
    }


class AttackSurfaceBuilder:
    def __init__(
        self,
        db,
        scan: WebScan,
        *,
        emit: Callable | None = None,
        log_event: Callable | None = None,
    ):
        self.db = db
        self.scan = scan
        self.emit = emit or (lambda *_a, **_k: None)
        self.log_event = log_event
        self._by_key: dict[str, WebScanNode] = {}
        for n in db.query(WebScanNode).filter_by(scan_id=scan.id).all():
            self._by_key[n.node_key] = n

    def ensure_root(self, url: str, *, hostname: str = "", ips: list[str] | None = None) -> WebScanNode:
        parsed = urlparse(url)
        host = (hostname or parsed.hostname or "target").lower()
        key = f"domain:{host}"
        return self._upsert(
            key=key,
            parent_id=None,
            node_type="domain",
            label=host,
            url=url,
            hostname=host,
            ip=(ips or [""])[0] if ips else "",
            protocol=(parsed.scheme or "https").lower(),
            port=parsed.port or (443 if (parsed.scheme or "https") == "https" else 80),
            depth=0,
        )

    def ensure_port(
        self,
        parent: WebScanNode,
        *,
        port: int,
        protocol: str = "tcp",
        service: str = "",
        state: str = "open",
    ) -> WebScanNode:
        if not port:
            return parent
        key = f"port:{parent.hostname}:{port}/{protocol}"
        label = f"{port}/{protocol}" + (f" {service}" if service else "")
        return self._upsert(
            key=key,
            parent_id=parent.id,
            node_type="port",
            label=label,
            url=parent.url,
            hostname=parent.hostname,
            ip=parent.ip,
            port=port,
            protocol=protocol,
            depth=parent.depth + 1,
            metadata={"state": state, "service": service},
        )

    def ensure_url_path(self, parent: WebScanNode, url: str, *, http_status: int | None = None) -> WebScanNode:
        if not url:
            return parent
        parsed = urlparse(url)
        path = parsed.path or "/"
        segments = [s for s in path.split("/") if s]
        current = parent
        built = ""
        if not segments:
            key = f"path:{parent.hostname}/"
            return self._upsert(
                key=key,
                parent_id=parent.id,
                node_type="path",
                label="/",
                url=url,
                hostname=parent.hostname,
                ip=parent.ip,
                protocol=parent.protocol or parsed.scheme or "",
                port=parent.port,
                http_status=http_status,
                depth=parent.depth + 1,
            )
        for i, part in enumerate(segments):
            built += "/" + part
            key = f"path:{parent.hostname}{built}"
            is_leaf = i == len(segments) - 1
            current = self._upsert(
                key=key,
                parent_id=current.id,
                node_type="endpoint" if is_leaf else "path",
                label=built,
                url=f"{parsed.scheme or parent.protocol or 'https'}://{parent.hostname}{built}",
                hostname=parent.hostname,
                ip=parent.ip,
                protocol=parent.protocol or parsed.scheme or "",
                port=parent.port,
                http_status=http_status if is_leaf else None,
                depth=parent.depth + 1 + i,
            )
        return current

    def ensure_api(self, parent: WebScanNode, url: str, *, method: str = "GET") -> WebScanNode:
        parsed = urlparse(url)
        path = parsed.path or "/"
        key = f"api:{method.upper()}:{parent.hostname}{path}"
        return self._upsert(
            key=key,
            parent_id=parent.id,
            node_type="api",
            label=f"{method.upper()} {path}",
            url=url,
            hostname=parent.hostname,
            protocol=parent.protocol,
            port=parent.port,
            depth=parent.depth + 1,
            metadata={"method": method.upper()},
        )

    def attach_finding(
        self,
        node: WebScanNode | None,
        *,
        severity: str,
        risk_score: int = 0,
        has_alert: bool = False,
    ) -> None:
        if not node:
            return
        node.finding_count = int(node.finding_count or 0) + 1
        node.severity = max_severity(node.severity, severity)
        node.risk_score = max(int(node.risk_score or 0), int(risk_score or 0))
        if has_alert:
            node.has_alert = True
        node.last_seen = utcnow()
        self.db.commit()
        self._propagate_ancestors(node)
        self.emit("webscan_node_updated", {"scan_id": self.scan.id, "node": _serialize_node(node)})

    def _propagate_ancestors(self, node: WebScanNode) -> None:
        parent_id = node.parent_id
        visited = set()
        while parent_id and parent_id not in visited:
            visited.add(parent_id)
            parent = self.db.get(WebScanNode, parent_id)
            if not parent:
                break
            parent.descendant_finding_count = int(parent.descendant_finding_count or 0) + 1
            parent.descendant_severity = max_severity(parent.descendant_severity, node.severity)
            if node.has_alert:
                parent.has_alert = True
            parent.last_seen = utcnow()
            self.db.commit()
            self.emit(
                "webscan_node_updated",
                {"scan_id": self.scan.id, "node": _serialize_node(parent)},
            )
            parent_id = parent.parent_id

    def _upsert(
        self,
        *,
        key: str,
        parent_id: int | None,
        node_type: str,
        label: str,
        url: str = "",
        hostname: str = "",
        ip: str = "",
        port: int | None = None,
        protocol: str = "",
        http_status: int | None = None,
        depth: int = 0,
        title: str = "",
        technology: str = "",
        metadata: dict | None = None,
    ) -> WebScanNode:
        existing = self._by_key.get(key)
        if existing:
            existing.last_seen = utcnow()
            if http_status is not None:
                existing.http_status = http_status
            if title:
                existing.title = title
            if technology:
                existing.technology = technology
            self.db.commit()
            self.emit("webscan_node_updated", {"scan_id": self.scan.id, "node": _serialize_node(existing)})
            return existing

        node = WebScanNode(
            scan_id=self.scan.id,
            target_id=self.scan.target_id,
            parent_id=parent_id,
            node_key=key,
            node_type=node_type,
            label=label[:500],
            url=(url or "")[:2000],
            hostname=hostname or "",
            ip=ip or "",
            port=port,
            protocol=protocol or "",
            http_status=http_status,
            title=title or "",
            technology=technology or "",
            depth=depth,
            metadata_json=json.dumps(metadata or {}),
            discovered_at=utcnow(),
            last_seen=utcnow(),
        )
        self.db.add(node)
        self.db.commit()
        self.db.refresh(node)
        self._by_key[key] = node
        self.scan.nodes_count = int(getattr(self.scan, "nodes_count", 0) or 0) + 1
        self.db.commit()
        payload = {
            "scan_id": self.scan.id,
            "target_id": self.scan.target_id,
            "node": _serialize_node(node),
        }
        self.emit("webscan_node_discovered", payload)
        self.emit("web_scan_node_discovered", payload)
        if self.log_event:
            self.log_event("DISCOVERY", f"Discovered {node_type} {label}", node_id=node.id, severity="INFO")
        return node


def build_tree_payload(db, scan_id: int) -> dict:
    nodes = (
        db.query(WebScanNode)
        .filter_by(scan_id=scan_id)
        .order_by(WebScanNode.depth.asc(), WebScanNode.id.asc())
        .all()
    )
    serialized = [_serialize_node(n) for n in nodes]
    children: dict[str, list[int]] = {}
    for n in serialized:
        pid = str(n["parent_id"] if n["parent_id"] is not None else "root")
        children.setdefault(pid, []).append(n["id"])
    return {
        "scan_id": scan_id,
        "nodes": serialized,
        "nodes_by_id": {str(n["id"]): n for n in serialized},
        "children_by_parent": children,
        "root_ids": children.get("root", []),
    }


def persist_scan_event(
    db,
    scan: WebScan,
    *,
    event_type: str,
    message: str,
    severity: str = "INFO",
    node_id: int | None = None,
    finding_id: int | None = None,
    payload: dict | None = None,
    emit: Callable | None = None,
) -> WebScanEvent:
    row = WebScanEvent(
        scan_id=scan.id,
        target_id=scan.target_id,
        event_type=event_type,
        message=(message or "")[:1000],
        severity=(severity or "INFO").upper(),
        node_id=node_id,
        finding_id=finding_id,
        payload_json=json.dumps(payload or {}),
        created_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    body = {
        "id": row.id,
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "event_type": event_type,
        "message": row.message,
        "severity": row.severity,
        "node_id": node_id,
        "finding_id": finding_id,
        "timestamp": row.created_at.isoformat() if row.created_at else None,
    }
    if emit:
        emit("webscan_log", body)
        emit("web_scan_log", body)
    return row

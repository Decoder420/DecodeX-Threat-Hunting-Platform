from __future__ import annotations

import csv
import io
import ipaddress
import re
from datetime import datetime, timezone

import requests

from .db import FeedSource, IOC, get_db, utcnow

# Keep sync responsive on demo hardware / managed laptops.
MAX_IOCS_PER_FEED = 500

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


class FeedCollector:
    def sync_enabled_feeds(self) -> dict[str, object]:
        db = get_db()
        summary = {
            "feeds_checked": 0,
            "ioc_added": 0,
            "ioc_updated": 0,
            "errors": [],
            "feeds": [],
        }
        now = utcnow()
        try:
            from flask import has_app_context

            in_request = has_app_context()
        except Exception:
            in_request = False

        try:
            feeds = db.query(FeedSource).filter_by(enabled=True).all()
            summary["feeds_checked"] = len(feeds)

            for feed in feeds:
                feed_result = {
                    "name": feed.name,
                    "ioc_type": feed.ioc_type,
                    "added": 0,
                    "updated": 0,
                    "error": None,
                }
                try:
                    added, updated = self.ingest_feed(
                        feed.url,
                        feed.name,
                        feed.ioc_type or "ip",
                        db=db,
                    )
                    feed.last_sync = now
                    feed.last_error = ""
                    feed_result["added"] = added
                    feed_result["updated"] = updated
                    summary["ioc_added"] += added
                    summary["ioc_updated"] += updated
                except Exception as exc:
                    feed.last_error = str(exc)
                    feed_result["error"] = str(exc)
                    summary["errors"].append({"feed": feed.name, "error": str(exc)})

                summary["feeds"].append(feed_result)

            db.commit()
            return summary
        finally:
            # Request-scoped sessions are closed by Flask teardown.
            if not in_request:
                db.close()

    def ingest_feed(
        self,
        url: str,
        source: str,
        ioc_type: str = "ip",
        db=None,
    ) -> tuple[int, int]:
        owns_db = db is None
        if db is None:
            db = get_db()

        response = requests.get(
            url,
            timeout=25,
            headers={"User-Agent": "ThreatHuntingPlatform/1.0"},
        )
        response.raise_for_status()

        values = self._extract_values(response.text, ioc_type)
        added = 0
        updated = 0
        now = utcnow()

        for value in values[:MAX_IOCS_PER_FEED]:
            existing = db.query(IOC).filter_by(type=ioc_type, value=value).first()
            if existing:
                existing.last_seen = now
                if not existing.source:
                    existing.source = source
                updated += 1
                continue

            db.add(
                IOC(
                    type=ioc_type,
                    value=value,
                    source=source,
                    first_seen=now,
                    last_seen=now,
                )
            )
            added += 1

        db.commit()
        if owns_db:
            db.close()
        return added, updated

    # Backwards-compatible name used elsewhere.
    def fetch_txt_feed(self, url: str, source: str, ioc_type: str = "ip", db=None) -> int:
        added, _updated = self.ingest_feed(url, source, ioc_type, db=db)
        return added

    def _extract_values(self, body: str, ioc_type: str) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()

        # ThreatFox / CSV style: "ts","id","ioc","ioc_type",...
        if "," in body and ('"domain"' in body or ", \"domain\"" in body or "ThreatFox" in body[:400]):
            for value in self._parse_csv_iocs(body, ioc_type):
                if value not in seen:
                    seen.add(value)
                    values.append(value)
            if values:
                return values

        for line in body.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or raw.startswith("//"):
                continue

            # URLhaus / some feeds put URL first; extract host when domain feed.
            candidate = raw.split()[0].strip().strip(",")
            candidate = candidate.strip('"').strip("'")

            if ioc_type == "domain" and ("://" in candidate or candidate.startswith("http")):
                candidate = self._host_from_url(candidate)

            # CSV leftover: take quoted third field if present
            if candidate.startswith('"') and "," in raw:
                parts = [p.strip().strip('"') for p in raw.split(",")]
                if len(parts) >= 3:
                    candidate = parts[2]

            normalized = self._normalize_value(candidate, ioc_type)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            values.append(normalized)

        return values

    def _parse_csv_iocs(self, body: str, ioc_type: str) -> list[str]:
        # Drop comment lines then parse as CSV.
        data_lines = [
            line for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not data_lines:
            return []

        # ThreatFox uses ", " separators; skipinitialspace keeps quoting valid.
        reader = csv.reader(io.StringIO("\n".join(data_lines)), skipinitialspace=True)
        values: list[str] = []
        for row in reader:
            if len(row) < 3:
                continue
            # ThreatFox recent domains: first_seen, id, ioc, ioc_type, ...
            ioc_value = (row[2] or "").strip().strip('"').strip("'")
            normalized = self._normalize_value(ioc_value, ioc_type)
            if normalized:
                values.append(normalized)
        return values

    def _host_from_url(self, url: str) -> str:
        try:
            without_scheme = url.split("://", 1)[-1]
            host = without_scheme.split("/", 1)[0]
            host = host.split("@")[-1]
            host = host.split(":")[0]
            return host.strip().lower()
        except Exception:
            return url

    def _normalize_value(self, value: str, ioc_type: str) -> str | None:
        if not value:
            return None
        value = value.strip().lower()
        if not value or len(value) > 512:
            return None

        if ioc_type == "ip":
            try:
                ipaddress.ip_address(value)
                return value
            except ValueError:
                return None

        if ioc_type == "domain":
            value = value.rstrip(".")
            if _DOMAIN_RE.match(value) and "." in value:
                return value
            return None

        if ioc_type == "hash":
            if _HASH_RE.match(value):
                return value.lower()
            return None

        return value

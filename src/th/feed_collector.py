from __future__ import annotations

from datetime import datetime, timezone

import requests

from .db import FeedSource, IOC, get_db


class FeedCollector:
    def sync_enabled_feeds(self) -> dict[str, object]:
        db = get_db()
        summary = {"feeds_checked": 0, "ioc_added": 0, "errors": []}
        now = datetime.now(timezone.utc)
        try:
            feeds = db.query(FeedSource).filter_by(enabled=True).all()
            summary["feeds_checked"] = len(feeds)

            for feed in feeds:
                try:
                    summary["ioc_added"] += self.fetch_txt_feed(feed.url, feed.name, feed.ioc_type, db=db)
                    feed.last_sync = now
                    feed.last_error = ""
                except Exception as exc:
                    feed.last_error = str(exc)
                    summary["errors"].append({"feed": feed.name, "error": str(exc)})

            db.commit()
            return summary
        finally:
            db.close()

    def fetch_txt_feed(self, url: str, source: str, ioc_type: str = "ip", db=None) -> int:
        owns_db = db is None
        if db is None:
            db = get_db()

        response = requests.get(url, timeout=15)
        response.raise_for_status()

        added = 0
        now = datetime.now(timezone.utc)

        for line in response.text.splitlines():
            value = line.strip()
            if not value or value.startswith("#") or len(value) > 512:
                continue

            existing = db.query(IOC).filter_by(type=ioc_type, value=value).first()
            if existing:
                existing.last_seen = now
                continue

            db.add(IOC(type=ioc_type, value=value, source=source, first_seen=now, last_seen=now))
            added += 1

        db.commit()
        if owns_db:
            db.close()
        return added

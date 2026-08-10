"""
Seed reference data: analyst accounts and default threat-intel feeds.

The admin account is already created automatically on first run (see
th.db._seed_defaults) with a random password printed to the console, or
TH_ADMIN_PASSWORD if you set it. This script is only for adding *additional*
analyst accounts and feed sources beyond that default admin.

Usage:
    PYTHONPATH=src python3 setup_admin.py
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from th.db import get_db, User, FeedSource
from werkzeug.security import generate_password_hash


def add_analyst(db, username: str, role: str = "analyst") -> None:
    if db.query(User).filter_by(username=username).first():
        print(f"  '{username}' already exists, skipping.")
        return
    password = getpass.getpass(f"  Set password for '{username}': ")
    if len(password) < 8:
        print("  Password too short (min 8 chars), skipping.")
        return
    db.add(User(username=username, password_hash=generate_password_hash(password), role=role))
    print(f"  Added user '{username}' ({role}).")


def setup() -> None:
    db = get_db()

    print("Add analyst accounts (leave username blank to skip):")
    while True:
        username = input("  Username: ").strip()
        if not username:
            break
        role = input("  Role [analyst/admin] (default analyst): ").strip() or "analyst"
        add_analyst(db, username, role)

    default_feeds = [
        {"name": "Abuse.ch IP Feed", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "enabled": True},
        {"name": "ThreatFox Domains", "url": "https://threatfox.abuse.ch/export/json/domains/", "enabled": True},
    ]
    existing = {f.name for f in db.query(FeedSource).all()}
    for feed in default_feeds:
        if feed["name"] not in existing:
            db.add(FeedSource(**feed))
            print(f"  Added feed source '{feed['name']}'.")

    db.commit()
    db.close()
    print("Done.")


if __name__ == "__main__":
    setup()

from __future__ import annotations

from pathlib import Path

import yaml


def sigma_to_local_rules(sigma_path: str | Path) -> list[dict]:
    path = Path(sigma_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}

    title = payload.get("title", path.stem)
    sigma_id = payload.get("id", path.stem)
    level = (payload.get("level") or "medium").lower()
    tags = payload.get("tags", [])
    mitre = extract_mitre(tags)
    detection = payload.get("detection", {})

    rules = []
    for key, value in detection.items():
        if key == "condition":
            continue
        if not isinstance(value, dict):
            continue

        conditions = []
        for field_name, field_value in value.items():
            if isinstance(field_value, list):
                for option in field_value:
                    conditions.append(
                        {
                            "type": "event_field_contains",
                            "field": normalize_field(field_name),
                            "value": str(option),
                        }
                    )
            else:
                conditions.append(
                    {
                        "type": "event_field_contains",
                        "field": normalize_field(field_name),
                        "value": str(field_value),
                    }
                )

        if conditions:
            rules.append(
                {
                    "id": f"sigma_{sigma_id}_{key}",
                    "description": title,
                    "severity": level,
                    "mitre": mitre,
                    "conditions": conditions,
                }
            )

    return rules


def extract_mitre(tags: list[str]) -> dict[str, str]:
    technique_id = ""
    tactic = ""
    for tag in tags:
        if tag.startswith("attack.t"):
            technique_id = tag.split(".")[-1].upper()
        elif tag.startswith("attack.") and not tactic:
            tactic = tag.split(".")[-1].replace("-", " ").title()
    return {
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": "Imported Sigma Detection" if technique_id else "",
    }


def normalize_field(field_name: str) -> str:
    lowered = field_name.lower()
    mapping = {
        "image": "process",
        "commandline": "commandline",
        "command_line": "commandline",
        "ipaddress": "ip",
        "destinationip": "ip",
        "user": "user",
        "computername": "host",
        "hostname": "host",
        "hashes": "file_hash",
        "domain": "domain",
    }
    return mapping.get(lowered, lowered)

from pathlib import Path
from typing import Dict, List, Optional

import yaml


class RuleEvaluator:
    def __init__(self, rule_file_path: str):
        path = Path(rule_file_path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[2] / path

        with path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}

        self.rule_file_path = path
        self.rules = payload.get("rules", [])

        # Seamlessly load any custom rules deployed via Detection Engineering Studio
        custom_path = path.parent / "custom_rules.yml"
        if custom_path.exists():
            try:
                with custom_path.open("r", encoding="utf-8") as custom_handle:
                    custom_payload = yaml.safe_load(custom_handle) or {}
                    self.rules.extend(custom_payload.get("rules", []))
            except Exception:
                pass

    def evaluate(
        self,
        event,
        ioc_ips: Optional[set] = None,
        ioc_domains: Optional[set] = None,
        ioc_hashes: Optional[set] = None,
    ) -> List[Dict]:
        alerts = []
        ioc_ips = ioc_ips or set()
        ioc_domains = ioc_domains or set()
        ioc_hashes = ioc_hashes or set()

        for rule in self.rules:
            if self._match_rule(rule, event, ioc_ips, ioc_domains, ioc_hashes):
                # Two rule shapes exist in this codebase: hunting_rules.yml
                # stores tactic/technique_id/technique_name as top-level
                # keys, while sigma_importer.py nests them under "mitre".
                # Support both so neither source silently loses its MITRE
                # mapping.
                mitre = rule.get("mitre") or {}
                alerts.append(
                    {
                        "id": rule["id"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "tactic": rule.get("tactic") or mitre.get("tactic", ""),
                        "technique_id": rule.get("technique_id") or mitre.get("technique_id", ""),
                        "technique_name": rule.get("technique_name") or mitre.get("technique_name", ""),
                        "event_id": getattr(event, "id", 0),
                        "host": getattr(event, "host", ""),
                        "user": getattr(event, "user", ""),
                        "process": getattr(event, "process", ""),
                        "ip": getattr(event, "ip", ""),
                        "domain": getattr(event, "domain", ""),
                        "file_hash": getattr(event, "file_hash", ""),
                        "commandline": getattr(event, "commandline", ""),
                        "timestamp": getattr(event, "timestamp", None),
                    }
                )

        return alerts

    def _match_rule(self, rule: dict, event, ioc_ips: set, ioc_domains: set, ioc_hashes: set) -> bool:
        for condition in rule.get("conditions", []):
            ctype = condition["type"]

            if ctype in ("event_field_contains", "event_field_contains_any"):
                field = condition["field"]
                target_text = (getattr(event, field, "") or "").lower()
                vals = condition.get("values")
                if vals is not None:
                    if not any(str(v).lower() in target_text for v in vals):
                        return False
                else:
                    val = condition.get("value")
                    if isinstance(val, list):
                        if not any(str(v).lower() in target_text for v in val):
                            return False
                    else:
                        if str(val).lower() not in target_text:
                            return False
            elif ctype == "ioc_ip_match":
                if getattr(event, "ip", "") not in ioc_ips:
                    return False
            elif ctype == "ioc_domain_match":
                if getattr(event, "domain", "") not in ioc_domains:
                    return False
            elif ctype == "ioc_hash_match":
                if getattr(event, "file_hash", "") not in ioc_hashes:
                    return False
            else:
                return False

        return True

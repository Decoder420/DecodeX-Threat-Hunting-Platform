"""
DecodeX Detection Engineering & Sigma Rule Management API
==========================================================
Provides endpoints for:
- Viewing active detection rules
- Validating Sigma & native YAML detection syntax
- Stateless in-memory dry-run testing against sample logs or ingested events
- Deploying custom rules to the rule engine
- Generating MITRE ATT&CK tactical coverage matrix
"""

import time
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from flask import Blueprint, jsonify, request
from sqlalchemy import desc

from .db import Event, IOC, SessionLocal, get_db
from .rule_evaluator import RuleEvaluator
from .sigma_importer import extract_mitre, normalize_field

logger = logging.getLogger("th.rules_api")

sigma_rules_bp = Blueprint("sigma_rules", __name__, url_prefix="/api/sigma")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULE_FILE = PROJECT_ROOT / "hunting_rules.yml"
CUSTOM_RULES_FILE = PROJECT_ROOT / "custom_rules.yml"

# Comprehensive Enterprise MITRE ATT&CK Tactics & Notable Techniques Catalog
ENTERPRISE_MITRE_MATRIX = [
    {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "techniques": [
            {"id": "T1078", "name": "Valid Accounts"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
            {"id": "T1566", "name": "Phishing"},
            {"id": "T1133", "name": "External Remote Services"},
        ],
    },
    {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "techniques": [
            {"id": "T1059.001", "name": "Command & Scripting: PowerShell"},
            {"id": "T1059.003", "name": "Command & Scripting: Windows Command Shell"},
            {"id": "T1204", "name": "User Execution: Malicious File"},
            {"id": "T1047", "name": "Windows Management Instrumentation"},
        ],
    },
    {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "techniques": [
            {"id": "T1053", "name": "Scheduled Task / Job"},
            {"id": "T1543", "name": "Create or Modify System Process"},
            {"id": "T1136", "name": "Create Account"},
            {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        ],
    },
    {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism"},
            {"id": "T1055", "name": "Process Injection"},
        ],
    },
    {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "techniques": [
            {"id": "T1218", "name": "System Binary Proxy Execution (LOLBins)"},
            {"id": "T1562", "name": "Impair Defenses: Disable Security Tools"},
            {"id": "T1070", "name": "Indicator Removal: Clear Event Logs"},
            {"id": "T1027", "name": "Obfuscated / Encoded Files or Information"},
        ],
    },
    {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "techniques": [
            {"id": "T1110", "name": "Brute Force / Credential Stuffing"},
            {"id": "T1003", "name": "OS Credential Dumping (LSASS/SAM)"},
            {"id": "T1555", "name": "Credentials from Password Stores"},
            {"id": "T1552", "name": "Unsecured Credentials"},
        ],
    },
    {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "techniques": [
            {"id": "T1087", "name": "Account Discovery"},
            {"id": "T1082", "name": "System Information Discovery"},
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1083", "name": "File and Directory Discovery"},
        ],
    },
    {
        "tactic_id": "TA0008",
        "tactic_name": "Lateral Movement",
        "techniques": [
            {"id": "T1021", "name": "Remote Services: SMB / RDP / SSH"},
            {"id": "T1570", "name": "Lateral Tool Transfer"},
            {"id": "T1550", "name": "Use Alternate Authentication Material"},
        ],
    },
    {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "techniques": [
            {"id": "T1005", "name": "Data from Local System"},
            {"id": "T1039", "name": "Data from Network Shared Drive"},
            {"id": "T1114", "name": "Email Collection"},
        ],
    },
    {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "techniques": [
            {"id": "T1071", "name": "Application Layer Protocol (Web/Beaconing)"},
            {"id": "T1573", "name": "Encrypted Channel"},
            {"id": "T1105", "name": "Ingress Tool Transfer"},
        ],
    },
    {
        "tactic_id": "TA0010",
        "tactic_name": "Exfiltration",
        "techniques": [
            {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            {"id": "T1048", "name": "Exfiltration Over Alternative Protocol (FTP/DNS)"},
            {"id": "T1567", "name": "Exfiltration Over Web Service"},
        ],
    },
    {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "techniques": [
            {"id": "T1486", "name": "Data Encrypted for Impact (Ransomware)"},
            {"id": "T1489", "name": "Service Stop"},
            {"id": "T1490", "name": "Inhibit System Recovery"},
        ],
    },
]


def _load_all_active_rules() -> List[Dict[str, Any]]:
    """Loads all active rules from default and custom rule files."""
    rules = []
    
    # 1. Load default hunting rules
    if DEFAULT_RULE_FILE.exists():
        try:
            with open(DEFAULT_RULE_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                for r in data.get("rules", []):
                    r_copy = dict(r)
                    r_copy["source_file"] = "hunting_rules.yml"
                    r_copy["format"] = "native"
                    rules.append(r_copy)
        except Exception as exc:
            logger.error("Failed loading default rules: %s", exc)

    # 2. Load custom rules if present
    if CUSTOM_RULES_FILE.exists():
        try:
            with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                for r in data.get("rules", []):
                    r_copy = dict(r)
                    r_copy["source_file"] = "custom_rules.yml"
                    r_copy["format"] = "custom"
                    rules.append(r_copy)
        except Exception as exc:
            logger.error("Failed loading custom rules: %s", exc)

    return rules


def _parse_rule_yaml(yaml_text: str) -> tuple[bool, Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]], List[str]]:
    """
    Parses YAML text supporting both Sigma format and native DecodeX format.
    Returns: (is_valid, parsed_raw, normalized_rules_list, error_messages)
    """
    errors = []
    if not yaml_text or not yaml_text.strip():
        return False, None, None, ["Rule YAML content cannot be empty."]

    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        pos = f"Line {mark.line + 1}, Col {mark.column + 1}: " if mark else ""
        return False, None, None, [f"{pos}{exc}"]

    if not isinstance(data, dict):
        return False, None, None, ["Top-level YAML structure must be a dictionary / mapping."]

    # Case A: Standard Sigma YAML format
    if "detection" in data:
        title = data.get("title")
        if not title:
            errors.append("Sigma rules must include a 'title' field.")
        
        detection = data.get("detection")
        if not isinstance(detection, dict) or not detection:
            errors.append("Sigma 'detection' field must be a non-empty mapping.")
        
        tags = data.get("tags", [])
        mitre = extract_mitre(tags)
        level = (data.get("level") or "medium").lower()
        sigma_id = data.get("id") or (title.lower().replace(" ", "_") if title else "custom_rule")

        normalized = []
        for key, value in (detection or {}).items():
            if key == "condition":
                continue
            if not isinstance(value, dict):
                continue

            conditions = []
            for field_name, field_value in value.items():
                norm_field = normalize_field(field_name)
                if isinstance(field_value, list):
                    conditions.append({
                        "type": "event_field_contains_any",
                        "field": norm_field,
                        "values": [str(opt) for opt in field_value],
                    })
                else:
                    conditions.append({
                        "type": "event_field_contains",
                        "field": norm_field,
                        "value": str(field_value),
                    })

            if conditions:
                normalized.append({
                    "id": f"sigma_{sigma_id}_{key}",
                    "description": title or sigma_id,
                    "severity": level,
                    "tactic": mitre.get("tactic", "Execution"),
                    "technique_id": mitre.get("technique_id", ""),
                    "technique_name": mitre.get("technique_name", ""),
                    "conditions": conditions,
                    "raw_format": "sigma",
                })

        if not normalized and not errors:
            errors.append("No valid detection conditions found in 'detection' section.")

        return len(errors) == 0, data, normalized, errors

    # Case B: Native DecodeX YAML rule format
    if "rules" in data and isinstance(data["rules"], list):
        rule_items = data["rules"]
    elif "conditions" in data:
        rule_items = [data]
    else:
        return False, data, None, [
            "YAML format unrecognized. Must be either standard Sigma (with 'title' and 'detection') "
            "or DecodeX format (with 'id', 'conditions', and 'severity')."
        ]

    normalized = []
    for idx, r in enumerate(rule_items):
        if not isinstance(r, dict):
            errors.append(f"Rule #{idx+1} is not a valid dictionary mapping.")
            continue
        
        rid = r.get("id")
        if not rid:
            errors.append(f"Rule #{idx+1} is missing mandatory 'id'.")

        conditions = r.get("conditions")
        if not conditions or not isinstance(conditions, list):
            errors.append(f"Rule '{rid or idx+1}' must define a non-empty 'conditions' list.")

        for c_idx, c in enumerate(conditions or []):
            if not isinstance(c, dict) or "type" not in c:
                errors.append(f"Rule '{rid}' condition #{c_idx+1} must define a 'type'.")

        normalized.append({
            "id": rid or f"rule_{idx+1}",
            "description": r.get("description", r.get("title", rid)),
            "severity": (r.get("severity") or "medium").lower(),
            "tactic": r.get("tactic", ""),
            "technique_id": r.get("technique_id", ""),
            "technique_name": r.get("technique_name", ""),
            "conditions": r.get("conditions", []),
            "raw_format": "native",
        })

    return len(errors) == 0, data, normalized, errors


# --- API Routes ---

@sigma_rules_bp.route("/rules", methods=["GET"])
def list_rules():
    """Returns all active rules loaded across system and custom rule sets."""
    all_rules = _load_all_active_rules()
    summaries = []
    for r in all_rules:
        mitre = r.get("mitre") or {}
        summaries.append({
            "id": r.get("id"),
            "description": r.get("description", ""),
            "severity": r.get("severity", "medium").lower(),
            "tactic": r.get("tactic") or mitre.get("tactic", ""),
            "technique_id": r.get("technique_id") or mitre.get("technique_id", ""),
            "technique_name": r.get("technique_name") or mitre.get("technique_name", ""),
            "conditions_count": len(r.get("conditions", [])),
            "source_file": r.get("source_file", "hunting_rules.yml"),
            "format": r.get("format", "native"),
        })

    return jsonify({
        "status": "ok",
        "count": len(summaries),
        "rules": summaries,
    })


@sigma_rules_bp.route("/rules/validate", methods=["POST"])
def validate_rule():
    """Validates Sigma or native YAML rule syntax and schema without executing."""
    payload = request.get_json(silent=True) or {}
    yaml_content = payload.get("yaml", "")

    is_valid, raw_ast, normalized, errors = _parse_rule_yaml(yaml_content)

    if not is_valid:
        return jsonify({
            "status": "error",
            "valid": False,
            "errors": errors,
        }), 400

    return jsonify({
        "status": "ok",
        "valid": True,
        "format": normalized[0].get("raw_format") if normalized else "unknown",
        "rule_count": len(normalized),
        "rules": normalized,
        "errors": [],
    })


@sigma_rules_bp.route("/rules/test", methods=["POST"])
def test_rule():
    """
    Stateless in-memory dry run of a candidate rule against sample log records.
    Can evaluate against:
    1. A custom JSON event object passed in `sample_event`
    2. A raw string log line passed in `sample_raw`
    3. The latest ingested events from the database (`use_recent_events=True`)
    """
    payload = request.get_json(silent=True) or {}
    yaml_content = payload.get("yaml", "")
    sample_event = payload.get("sample_event")
    sample_raw = payload.get("sample_raw", "")
    use_recent = payload.get("use_recent_events", False)

    is_valid, _, normalized_rules, errors = _parse_rule_yaml(yaml_content)
    if not is_valid:
        return jsonify({"status": "error", "valid": False, "errors": errors}), 400

    start_time = time.perf_counter()
    evaluator = RuleEvaluator.__new__(RuleEvaluator)
    evaluator.rules = normalized_rules

    # Assemble test events list
    test_events = []
    
    if sample_event and isinstance(sample_event, dict):
        class MockEvent:
            pass
        me = MockEvent()
        for k, v in sample_event.items():
            setattr(me, k, str(v) if v is not None else "")
        setattr(me, "id", 9999)
        test_events.append(me)

    elif sample_raw:
        class RawLogEvent:
            id = 9999
            host = "test-endpoint"
            user = "analyst"
            process = "powershell.exe" if "powershell" in sample_raw.lower() else "process"
            commandline = sample_raw
            ip = "127.0.0.1"
            domain = ""
            file_hash = ""
            timestamp = None
        test_events.append(RawLogEvent())

    elif use_recent:
        db = get_db()
        recent = db.query(Event).order_by(desc(Event.timestamp)).limit(20).all()
        test_events.extend(recent)
    else:
        # Default fallback test event if none provided
        class DefaultMockEvent:
            id = 1
            host = "WIN-PROD-01"
            user = "Administrator"
            process = "powershell.exe"
            commandline = "powershell.exe -w hidden -nop -enc JABzACAAPQAgAE4AZQB3..."
            ip = "45.148.10.12"
            domain = "malicious.example.com"
            file_hash = "44d88612fea8a8f36de82e1278abb02f"
            timestamp = None
        test_events.append(DefaultMockEvent())

    # Build active IOC sets for evaluation
    ioc_ips = set()
    ioc_domains = set()
    ioc_hashes = set()
    try:
        db = get_db()
        for ioc in db.query(IOC).all():
            if ioc.type == "ip": ioc_ips.add(ioc.value)
            elif ioc.type == "domain": ioc_domains.add(ioc.value.lower())
            elif ioc.type == "hash": ioc_hashes.add(ioc.value.lower())
    except Exception:
        pass

    matches = []
    for ev in test_events:
        alerts = evaluator.evaluate(ev, ioc_ips, ioc_domains, ioc_hashes)
        for alert in alerts:
            matches.append({
                "rule_id": alert["id"],
                "severity": alert["severity"],
                "description": alert["description"],
                "tactic": alert.get("tactic"),
                "technique_id": alert.get("technique_id"),
                "matched_event": {
                    "host": getattr(ev, "host", ""),
                    "user": getattr(ev, "user", ""),
                    "process": getattr(ev, "process", ""),
                    "commandline": getattr(ev, "commandline", ""),
                    "ip": getattr(ev, "ip", ""),
                },
            })

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return jsonify({
        "status": "ok",
        "matched": len(matches) > 0,
        "match_count": len(matches),
        "evaluated_events_count": len(test_events),
        "execution_time_ms": elapsed_ms,
        "matches": matches,
    })


@sigma_rules_bp.route("/rules/save", methods=["POST"])
def save_custom_rule():
    """
    Appends or saves a validated rule into custom_rules.yml.
    Protected: Restricted to Analyst and Admin roles.
    """
    # Role check using database token lookup
    from .db import get_db, get_user_for_token
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.split("Bearer ", 1)[-1].strip() if "Bearer " in auth_header else auth_header.strip()
    
    user = None
    if token:
        db = get_db()
        user = get_user_for_token(db, token)

    if not user or getattr(user, "role", None) not in ("admin", "analyst"):
        return jsonify({
            "status": "error",
            "message": "Unauthorized. Only Analyst and Admin roles can deploy detection rules."
        }), 403

    payload = request.get_json(silent=True) or {}
    yaml_content = payload.get("yaml", "")

    is_valid, _, normalized, errors = _parse_rule_yaml(yaml_content)
    if not is_valid or not normalized:
        return jsonify({"status": "error", "message": "Invalid rule YAML.", "errors": errors}), 400

    # Load existing custom rules
    existing_rules = []
    if CUSTOM_RULES_FILE.exists():
        try:
            with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                existing_rules = data.get("rules", [])
        except Exception:
            existing_rules = []

    # Merge / replace by id
    new_ids = {r["id"] for r in normalized}
    retained_rules = [r for r in existing_rules if r.get("id") not in new_ids]
    retained_rules.extend(normalized)

    try:
        with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
            yaml.dump({"rules": retained_rules}, f, sort_keys=False)
    except Exception as exc:
        logger.error("Failed saving custom rules file: %s", exc)
        return jsonify({"status": "error", "message": f"Failed writing custom rules: {exc}"}), 500

    return jsonify({
        "status": "ok",
        "message": f"Successfully deployed {len(normalized)} rule(s) to detection engine.",
        "deployed_ids": list(new_ids),
        "total_custom_rules": len(retained_rules),
    })


@sigma_rules_bp.route("/mitre-matrix", methods=["GET"])
def get_mitre_matrix():
    """
    Computes an interactive MITRE ATT&CK Enterprise coverage grid.
    Aggregates active rules by Technique ID and Tactic ID.
    """
    all_rules = _load_all_active_rules()

    # Map techniques to rules
    rule_map_by_technique: Dict[str, List[Dict[str, Any]]] = {}
    covered_tactics_set = set()

    for r in all_rules:
        tech_id = (r.get("technique_id") or "").strip().upper()
        if tech_id:
            if tech_id not in rule_map_by_technique:
                rule_map_by_technique[tech_id] = []
            rule_map_by_technique[tech_id].append({
                "id": r.get("id"),
                "description": r.get("description", ""),
                "severity": r.get("severity", "medium"),
                "tactic": r.get("tactic", ""),
            })
            if r.get("tactic"):
                covered_tactics_set.add(r.get("tactic").lower())

    matrix_output = []
    total_techniques_count = 0
    covered_techniques_count = 0

    for tactic in ENTERPRISE_MITRE_MATRIX:
        tactic_copy = dict(tactic)
        tech_list = []
        for tech in tactic["techniques"]:
            total_techniques_count += 1
            matching_rules = rule_map_by_technique.get(tech["id"], [])
            is_covered = len(matching_rules) > 0
            if is_covered:
                covered_techniques_count += 1
            tech_list.append({
                "id": tech["id"],
                "name": tech["name"],
                "covered": is_covered,
                "rule_count": len(matching_rules),
                "rules": matching_rules,
            })

        tactic_copy["techniques"] = tech_list
        tactic_copy["covered"] = any(t["covered"] for t in tech_list)
        matrix_output.append(tactic_copy)

    coverage_pct = round((covered_techniques_count / total_techniques_count * 100), 1) if total_techniques_count > 0 else 0.0

    return jsonify({
        "status": "ok",
        "summary": {
            "total_tactics": len(ENTERPRISE_MITRE_MATRIX),
            "covered_tactics": len([t for t in matrix_output if t["covered"]]),
            "total_techniques": total_techniques_count,
            "covered_techniques": covered_techniques_count,
            "coverage_percentage": coverage_pct,
            "active_rules_count": len(all_rules),
        },
        "tactics": matrix_output,
    })

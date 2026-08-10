from datetime import datetime
from types import SimpleNamespace

from src.th.pipeline import build_ioc_sets, summarize_alerts
from src.th.rule_evaluator import RuleEvaluator


def test_rule_evaluator_matches_ioc_types(tmp_path):
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text(
        """
rules:
  - id: ip_hit
    description: IOC IP matched
    conditions:
      - type: ioc_ip_match
    severity: medium
  - id: domain_hit
    description: IOC domain matched
    conditions:
      - type: ioc_domain_match
    severity: high
  - id: hash_hit
    description: IOC hash matched
    conditions:
      - type: ioc_hash_match
    severity: high
""".strip(),
        encoding="utf-8",
    )

    event = SimpleNamespace(
        timestamp=datetime(2025, 12, 29, 12, 0, 0),
        host="PC-01",
        user="alice",
        process="powershell.exe",
        ip="45.148.10.12",
        domain="malicious.example.com",
        file_hash="44d88612fea8a8f36de82e1278abb02f",
    )

    alerts = RuleEvaluator(str(rule_file)).evaluate(
        event,
        ioc_ips={"45.148.10.12"},
        ioc_domains={"malicious.example.com"},
        ioc_hashes={"44d88612fea8a8f36de82e1278abb02f"},
    )

    assert [alert["id"] for alert in alerts] == ["ip_hit", "domain_hit", "hash_hit"]


def test_rule_evaluator_reads_top_level_mitre_fields(tmp_path):
    """Regression test: hunting_rules.yml stores tactic/technique_id as
    top-level keys (not nested under "mitre"). The evaluator must read
    both shapes, or every alert silently loses its MITRE mapping."""
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text(
        """
rules:
  - id: flat_mitre
    description: Flat-style rule (hunting_rules.yml format)
    severity: high
    tactic: Credential Access
    technique_id: T1110
    conditions:
      - type: event_field_contains
        field: commandline
        value: failed login
""".strip(),
        encoding="utf-8",
    )

    event = SimpleNamespace(
        timestamp=datetime(2025, 12, 29, 12, 0, 0),
        host="DC-01", user="eve", process="winlogon.exe",
        commandline="Failed login attempt", ip="", domain="", file_hash="",
    )

    alerts = RuleEvaluator(str(rule_file)).evaluate(event)

    assert len(alerts) == 1
    assert alerts[0]["tactic"] == "Credential Access"
    assert alerts[0]["technique_id"] == "T1110"


def test_rule_evaluator_reads_nested_mitre_fields(tmp_path):
    """Sigma-imported rules (see sigma_importer.py) nest tactic/technique_id
    under a "mitre" dict — that shape must keep working too."""
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text(
        """
rules:
  - id: nested_mitre
    description: Nested-style rule (sigma_importer.py format)
    severity: high
    mitre:
      tactic: Execution
      technique_id: T1059.001
      technique_name: PowerShell
    conditions:
      - type: event_field_contains
        field: process
        value: powershell
""".strip(),
        encoding="utf-8",
    )

    event = SimpleNamespace(
        timestamp=datetime(2025, 12, 29, 12, 0, 0),
        host="WEB-01", user="svc", process="powershell.exe",
        commandline="", ip="", domain="", file_hash="",
    )

    alerts = RuleEvaluator(str(rule_file)).evaluate(event)

    assert len(alerts) == 1
    assert alerts[0]["tactic"] == "Execution"
    assert alerts[0]["technique_id"] == "T1059.001"


def test_build_ioc_sets_groups_types():
    grouped = build_ioc_sets(
        [
            SimpleNamespace(type="ip", value="1.1.1.1"),
            SimpleNamespace(type="domain", value="example.org"),
            SimpleNamespace(type="hash", value="deadbeef"),
        ]
    )

    assert grouped == {
        "ip": {"1.1.1.1"},
        "domain": {"example.org"},
        "hash": {"deadbeef"},
    }


def test_summarize_alerts_counts_severity_breakdown():
    summary = summarize_alerts(
        [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "high"},
        ]
    )

    assert summary["total_alerts"] == 3
    assert summary["high_or_above"] == 2
    assert summary["by_severity"] == {"high": 2, "medium": 1}

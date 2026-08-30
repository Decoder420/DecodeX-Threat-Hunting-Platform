try:
    from rich import print
except ImportError:
    pass

from .db import Alert, IngestionState, get_db
from .pipeline import DEFAULT_RULE_FILE, build_dashboard_summary, refresh_hunting_state, unique_alerts
from .rule_evaluator import RuleEvaluator
from th.anomaly import AnomalyDetector


def main() -> None:
    print("[bold green]DecodeX Threat Hunting Platform started[/bold green]")
    db = get_db()

    try:
        evaluator = RuleEvaluator(str(DEFAULT_RULE_FILE))
        refresh_stats = refresh_hunting_state(db, evaluator)
        print(f"[cyan]IOCs added:[/cyan] {refresh_stats['iocs_added']}")
        print(f"[cyan]Events added:[/cyan] {refresh_stats['events_added']}")
        print(f"[cyan]Events skipped:[/cyan] {refresh_stats['events_skipped']}")
        print(f"[cyan]Alerts persisted:[/cyan] {refresh_stats['alerts_added']}")
        print(f"[cyan]Duplicate alerts removed:[/cyan] {refresh_stats['duplicate_alerts_removed']}")

        alerts = unique_alerts(db.query(Alert).order_by(Alert.event_timestamp.desc(), Alert.id.desc()).all())
        summary = build_dashboard_summary([], [], alerts, db.query(IngestionState).all())

        for alert in alerts:
            print(
                "[red]ALERT "
                f"[{alert.severity.upper()}]: {alert.rule_id} "
                f"host={alert.host} ip={alert.ip or '-'} domain={alert.domain or '-'} "
                f"process={alert.process or '-'} "
                f"mitre={alert.technique_id or '-'} - {alert.description}[/red]"
            )

        if not alerts:
            print("[green]No threats detected[/green]")
        else:
            print(
                "[bold yellow]Alert summary:[/bold yellow] "
                f"{summary['total_alerts']} total, "
                f"{summary['high_or_above']} high-or-above, "
                f"breakdown={summary['by_severity']}"
            )
    finally:
        db.close()


if __name__ == "__main__":
    main()

"""CLI for AI SOC Analyst."""

import argparse
import asyncio
import json
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from soc_analyst.agents.soc_analyst import SOCAnalystAgent
from soc_analyst.config import get_settings
from soc_analyst.connectors.elasticsearch_client import ElasticsearchClient
from soc_analyst.services.alert_processor import AlertProcessor
from soc_analyst.services.report_generator import render_incident_report

console = Console()


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "soc_analyst.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=args.reload,
    )


async def cmd_analyze(args: argparse.Namespace) -> None:
    processor = AlertProcessor()
    es = ElasticsearchClient()

    if args.demo:
        alerts = processor.seed_demo_alerts()
        console.print("[yellow]Running in demo mode (no Elasticsearch required)[/yellow]")
    elif args.alert_id:
        alert = es.get_alert_by_id(args.alert_id)
        if not alert:
            console.print(f"[red]Alert {args.alert_id} not found[/red]")
            sys.exit(1)
        alerts = [alert]
    else:
        alerts = es.search_alerts(hours_back=args.hours, limit=args.limit)

    for alert in alerts:
        console.print(f"\n[bold cyan]Analyzing alert {alert.id}...[/bold cyan]")
        analysis = await processor.analyze_single(alert)

        table = Table(title=f"Alert Analysis — {alert.rule_description}")
        table.add_column("Field", style="dim")
        table.add_column("Value")
        table.add_row("Severity", analysis.severity.value.upper())
        table.add_row("Priority Score", f"{analysis.priority_score:.1f}/100")
        table.add_row("Summary", analysis.summary)
        table.add_row("Threat", analysis.threat_explanation)
        table.add_row(
            "MITRE",
            ", ".join(f"{m.technique_id} ({m.technique_name})" for m in analysis.mitre_mappings)
            or "None mapped",
        )
        table.add_row("False Positive", analysis.false_positive_likelihood)
        console.print(table)

        if analysis.remediation_steps:
            console.print("\n[bold green]Remediation Steps:[/bold green]")
            for step in sorted(analysis.remediation_steps, key=lambda s: s.priority):
                console.print(f"  [{step.priority}] {step.action}")
                console.print(f"      [dim]{step.rationale}[/dim]")

        if args.json:
            console.print_json(json.dumps(analysis.model_dump(), default=str))


async def cmd_prioritize(args: argparse.Namespace) -> None:
    processor = AlertProcessor()
    queue = await processor.get_prioritized_queue(args.hours, args.limit)

    table = Table(title="Prioritized Alert Queue")
    table.add_column("Rank", style="dim")
    table.add_column("Score", style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Agent")
    table.add_column("MITRE #")

    for i, item in enumerate(queue, 1):
        alert = item["alert"]
        sev = item["severity"]
        color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}.get(
            sev, "white"
        )
        table.add_row(
            str(i),
            f"[{color}]{item['priority_score']:.0f}[/{color}]",
            f"[{color}]{sev.upper()}[/{color}]",
            alert.get("rule_description", "")[:50],
            alert.get("agent_name", ""),
            str(item["mitre_count"]),
        )

    console.print(table)


async def cmd_report(args: argparse.Namespace) -> None:
    processor = AlertProcessor()
    es = ElasticsearchClient()
    agent = SOCAnalystAgent()

    if args.demo:
        alerts = processor.seed_demo_alerts()
    else:
        alerts = es.search_alerts(hours_back=args.hours, min_rule_level=7, limit=args.limit)

    analyses = []
    for alert in alerts:
        analysis = await processor.analyze_single(alert)
        analyses.append(analysis)

    report = agent.generate_incident_report(analyses, incident_title=args.title)
    markdown = render_incident_report(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(markdown)
        console.print(f"[green]Report saved to {args.output}[/green]")
    else:
        console.print(Panel(markdown, title="Incident Report"))


async def cmd_correlate(args: argparse.Namespace) -> None:
    processor = AlertProcessor()
    es = ElasticsearchClient()
    from soc_analyst.services.correlation import AlertCorrelator

    if args.demo:
        alerts = processor.seed_demo_alerts()
        console.print("[yellow]Running in demo mode (no Elasticsearch required)[/yellow]")
    else:
        alerts = es.search_alerts(hours_back=args.hours, limit=args.limit)

    incidents = AlertCorrelator.correlate(alerts)

    table = Table(title="Correlated Security Incidents")
    table.add_column("Incident ID")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Alerts Count")
    table.add_column("Common Agent")
    table.add_column("Common IP")
    table.add_column("Common User")

    for inc in incidents:
        color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}.get(
            inc.severity.value, "white"
        )
        table.add_row(
            inc.incident_id,
            inc.title,
            f"[{color}]{inc.severity.value.upper()}[/{color}]",
            str(len(inc.alerts)),
            inc.common_agent or "-",
            inc.common_ip or "-",
            inc.common_user or "-",
        )

    console.print(table)


async def cmd_watch(args: argparse.Namespace) -> None:
    processor = AlertProcessor()
    console.print("[bold]Watching for new alerts (Ctrl+C to stop)...[/bold]")

    try:
        async for analysis in processor.stream_new_alerts():
            color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
            }.get(analysis.severity.value, "white")

            console.print(
                Panel(
                    f"[bold]{analysis.summary}[/bold]\n\n"
                    f"Severity: [{color}]{analysis.severity.value.upper()}[/{color}] "
                    f"(Score: {analysis.priority_score:.0f})\n"
                    f"MITRE: {', '.join(m.technique_id for m in analysis.mitre_mappings)}\n"
                    f"Next: {analysis.recommended_next_steps[0] if analysis.recommended_next_steps else 'Review manually'}",
                    title=f"New Alert — {analysis.alert_id}",
                )
            )
    except KeyboardInterrupt:
        processor.stop()
        console.print("\n[yellow]Stopped watching.[/yellow]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI SOC Analyst — Investigate Wazuh/ELK alerts with AI"
    )
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Start the API server")
    serve_p.add_argument("--reload", action="store_true")
    serve_p.set_defaults(func=cmd_serve)

    analyze_p = sub.add_parser("analyze", help="Analyze alerts")
    analyze_p.add_argument("--alert-id", help="Specific alert ID")
    analyze_p.add_argument("--hours", type=int, default=24)
    analyze_p.add_argument("--limit", type=int, default=10)
    analyze_p.add_argument("--demo", action="store_true")
    analyze_p.add_argument("--json", action="store_true")
    analyze_p.set_defaults(func=lambda a: asyncio.run(cmd_analyze(a)))

    prio_p = sub.add_parser("prioritize", help="Show prioritized alert queue")
    prio_p.add_argument("--hours", type=int, default=24)
    prio_p.add_argument("--limit", type=int, default=20)
    prio_p.set_defaults(func=lambda a: asyncio.run(cmd_prioritize(a)))

    report_p = sub.add_parser("report", help="Generate incident report")
    report_p.add_argument("--title", default="Security Incident")
    report_p.add_argument("--hours", type=int, default=24)
    report_p.add_argument("--limit", type=int, default=10)
    report_p.add_argument("--demo", action="store_true")
    report_p.add_argument("-o", "--output", help="Output file path")
    report_p.set_defaults(func=lambda a: asyncio.run(cmd_report(a)))

    watch_p = sub.add_parser("watch", help="Real-time alert monitoring")
    watch_p.set_defaults(func=lambda a: asyncio.run(cmd_watch(a)))

    correlate_p = sub.add_parser("correlate", help="Show correlated incidents")
    correlate_p.add_argument("--hours", type=int, default=24)
    correlate_p.add_argument("--limit", type=int, default=100)
    correlate_p.add_argument("--demo", action="store_true")
    correlate_p.set_defaults(func=lambda a: asyncio.run(cmd_correlate(a)))

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()

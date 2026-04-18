import click
import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BANNER = """
██████╗ ████████╗██╗  ██╗
██╔══██╗╚══██╔══╝██║  ██║
██████╔╝   ██║   ███████║
██╔═══╝    ██║   ██╔══██║
██║        ██║   ██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═╝

Persistent Threat Hunter v0.1
UEFI Rootkit & Anti-Forensics Detection Platform
"""


def print_banner():
    console.print(Panel(BANNER, style="bold red"))
    console.print(
        f"[dim]Session started: "
        f"{datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]\n"
    )


def generate_case_id() -> str:
    return f"PTH-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}"


# CLI group 

@click.group()
def cli():
    """Persistent Threat Hunter - Forensic Analysis Platform"""
    pass


# analyze command - full pipeline

@cli.command()
@click.option("--firmware",  default=None, help="Path to firmware dump (.bin / .fd)")
@click.option("--disk",      default=None, help="Path to disk image (.dd / .img)")
@click.option("--evtx",      default=None, help="Path to event log JSON file")
@click.option("--case-id",   default=None, help="Custom case ID (auto-generated if not set)")
@click.option("--output",    default="./output", help="Output directory for reports")
@click.option("--analyst",   default="PTH Automated Analysis", help="Analyst name for report")
def analyze(firmware, disk, evtx, case_id, output, analyst):
    """Run the full forensic analysis pipeline"""
    print_banner()

    if not any([firmware, disk, evtx]):
        console.print(
            "[red]Error:[/red] Provide at least one input:\n"
            "  --firmware  path to firmware dump\n"
            "  --disk      path to disk image\n"
            "  --evtx      path to event log JSON"
        )
        sys.exit(1)

    case = case_id or generate_case_id()
    console.print(f"[bold green]Case ID:[/bold green] {case}\n")

    firmware_findings    = []
    antiforensics_findings = []

    # stage 1: Firmware Analysis

    if firmware:
        console.print("[bold cyan]Stage 1: Firmware Analysis[/bold cyan]")
        console.rule()

        from firmware_module.acquisition import FirmwareDumper
        from firmware_module.uefi_parser import UEFIParser
        from firmware_module.rootkit_detector import RootkitDetector

        dumper = FirmwareDumper()
        acquired = dumper.load_from_file(firmware)

        if not acquired:
            console.print("[red]Could not load firmware file - skipping firmware analysis[/red]")
        else:
            dumper.verify_integrity(acquired)

            console.print("\n[bold]Parsing UEFI structure...[/bold]")
            parser = UEFIParser(acquired["path"] and Path(firmware).read_bytes()).parse()

            all_drivers = parser.drivers + parser.smm_modules
            console.print(f"\n[bold]Scanning {len(all_drivers)} driver(s) for rootkits...[/bold]")

            detector = RootkitDetector()
            scan_results = detector.scan_all_drivers(all_drivers)
            firmware_findings = scan_results["flagged"]

            console.print(
                f"\n[bold]Firmware scan complete:[/bold] "
                f"[red]{len(firmware_findings)}[/red] driver(s) flagged"
            )

    else:
        console.print("[dim]Stage 1: Firmware Analysis - skipped (no --firmware provided)[/dim]\n")

    # stage 2: Anti-Forensic Detection
    
    console.print("\n[bold cyan]Stage 2: Anti-Forensics Detection[/bold cyan]")
    console.rule()

    from anti_forensics_module.log_gap_analyzer import LogGapAnalyzer

    if evtx:
        console.print(f"[bold]Analyzing event log:[/bold] {evtx}")
        analyzer = LogGapAnalyzer()
        log_findings = analyzer.analyze_json_file(evtx)
        antiforensics_findings += log_findings
        console.print(f"  Found [red]{len(log_findings)}[/red] log anomaly/anomalies")
    else:
        console.print("[dim]Event log analysis skipped - no --evtx provided[/dim]")

    if disk:
        console.print(f"\n[bold]Disk image provided:[/bold] {disk}")
        console.print("[dim]Full MFT timestomp analysis requires Linux + pytsk3 - skipping on Windows[/dim]")
    else:
        console.print("[dim]Disk analysis skipped - no --disk provided[/dim]")

    # stage 3: Correlation

    console.print("\n[bold cyan]Stage 3: Correlation Engine[/bold cyan]")
    console.rule()

    from correlation_engine.timeline_builder import TimelineBuilder
    from correlation_engine.confidence_scorer import ConfidenceScorer
    from correlation_engine.attack_graph import AttackGraphBuilder

    builder = TimelineBuilder()
    builder.add_firmware_findings(firmware_findings)
    builder.add_antiforensics_findings(antiforensics_findings)
    timeline = builder.build()

    scorer = ConfidenceScorer()
    confidence = scorer.calculate(timeline)

    graph_builder = AttackGraphBuilder()
    attack_graph = graph_builder.build(timeline)

    ascii_chain = graph_builder.render_ascii(attack_graph)
    if ascii_chain:
        console.print(f"\n[bold]Attack Chain:[/bold]\n{ascii_chain}")

    # stage 4: Report Generation

    console.print("\n[bold cyan]Stage 4: Report Generation[/bold cyan]")
    console.rule()

    from reporting.report_generator import ReportGenerator

    reporter = ReportGenerator(output_dir=output)
    report_data = reporter.build_report_data(
        case_id=case,
        firmware_findings=firmware_findings,
        antiforensics_findings=antiforensics_findings,
        timeline=timeline,
        attack_graph=attack_graph,
        confidence=confidence,
        analyst=analyst,
    )
    outputs = reporter.generate(report_data)

    # Final Summary

    console.print("\n")
    console.rule()
    console.print(f"[bold green]Analysis Complete - Case {case}[/bold green]")

    score   = confidence["confidence_score"]
    verdict = confidence["verdict"]
    color   = "red" if score >= 65 else "yellow" if score >= 40 else "green"

    console.print(f"[bold]Confidence Score:[/bold] [{color}]{score}%[/{color}]")
    console.print(f"[bold]Verdict:[/bold] {verdict}")
    console.print(f"[bold]Reports saved to:[/bold] {output}/")

    table = Table(show_header=True, header_style="bold dim")
    table.add_column("Format")
    table.add_column("Path")
    for fmt, path in outputs.items():
        table.add_row(fmt.upper(), path)
    console.print(table)


# antiforensic command - standalone

@cli.command()
@click.option("--evtx",  default=None, help="Path to event log JSON file")
@click.option("--disk",  default=None, help="Path to disk image")
@click.option("--live",  is_flag=True,  help="Read live Windows event logs")
def antiforensics(evtx, disk, live):
    """Run only the anti-forensics detection module"""
    print_banner()

    from anti_forensics_module.log_gap_analyzer import LogGapAnalyzer
    from anti_forensics_module.timestomp_detector import TimestompDetector

    if live:
        console.print("[bold]Reading live Windows event log...[/bold]")
        analyzer = LogGapAnalyzer()
        findings = analyzer.analyze_live_windows_logs("Security")
    elif evtx:
        console.print(f"[bold]Analyzing:[/bold] {evtx}")
        analyzer = LogGapAnalyzer()
        findings = analyzer.analyze_json_file(evtx)
    else:
        console.print("[red]Error:[/red] Provide --evtx, --disk, or --live")
        return

    summary = LogGapAnalyzer().get_summary() if not findings else None

    if findings:
        console.print(f"\n[red]{len(findings)} finding(s) detected:[/red]")
        for f in findings:
            sev   = f.get("severity", "MEDIUM")
            color = "red" if sev == "CRITICAL" else "yellow"
            console.print(
                f"  [{color}][{sev}][/{color}] "
                f"{f.get('type')} - {f.get('detail')}"
            )
    else:
        console.print("[green]No anti-forensics activity detected[/green]")


# firmware command - standalone

@cli.command()
@click.argument("firmware_path")
@click.option("--output", default="./output", help="Output directory")
def firmware(firmware_path, output):
    """Analyze a single firmware dump for rootkits"""
    print_banner()

    from firmware_module.acquisition import FirmwareDumper
    from firmware_module.uefi_parser import UEFIParser
    from firmware_module.rootkit_detector import RootkitDetector

    console.print(f"[bold]Analyzing firmware:[/bold] {firmware_path}\n")

    dumper   = FirmwareDumper()
    acquired = dumper.load_from_file(firmware_path)

    if not acquired:
        console.print("[red]Failed to load firmware file[/red]")
        return

    blob   = Path(firmware_path).read_bytes()
    parser = UEFIParser(blob).parse()

    summary = parser.get_summary()
    console.print(f"\n[bold]Structure:[/bold]")
    console.print(f"  Volumes : {summary['volume_count']}")
    console.print(f"  FFS Files: {summary['ffs_count']}")
    console.print(f"  DXE Drivers: {summary['driver_count']}")
    console.print(f"  SMM Modules: {summary['smm_count']}")

    all_drivers = parser.drivers + parser.smm_modules
    if not all_drivers:
        console.print("\n[yellow]No drivers found to scan[/yellow]")
        return

    console.print(f"\n[bold]Scanning {len(all_drivers)} driver(s)...[/bold]")
    detector = RootkitDetector()
    results  = detector.scan_all_drivers(all_drivers)

    if results["flagged"]:
        console.print(f"\n[red]⚠ {len(results['flagged'])} driver(s) flagged[/red]")
    else:
        console.print("\n[green]✓ No rootkit indicators found[/green]")


# report command - regenerate from existing data

@cli.command()
@click.option("--case-id", required=True, help="Case ID to generate report for")
@click.option("--output",  default="./output", help="Output directory")
def report(case_id, output):
    """Regenerate report for a completed analysis"""
    print_banner()

    import json
    json_path = Path(output) / f"{case_id}_report.json"

    if not json_path.exists():
        console.print(f"[red]Error:[/red] No data found for case {case_id}")
        console.print(f"[dim]Expected: {json_path}[/dim]")
        return

    data = json.loads(json_path.read_text(encoding="utf-8"))

    from reporting.report_generator import ReportGenerator
    reporter = ReportGenerator(output_dir=output)
    outputs  = reporter.generate(data)

    console.print(f"[green]Report regenerated:[/green]")
    for fmt, path in outputs.items():
        console.print(f"  {fmt.upper()}: {path}")


if __name__ == "__main__":
    cli()
import json
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from rich.console import Console

_con = Console()


class ReportGenerator:
    """
    Generates forensic reports from analysis results.

    Two output format:
        HTML: full styled report using Jinja2 template
        Text: Plain text summary for CLI output and logging

    Input is a ReportData dict built from all module outputs.
    """

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True
        )
    
    # Public API

    def generate(self, report_data: dict) -> dict:
        """Generates both HTML and text reports."""
        case_id = report_data.get("case_id", "UNKNOWN")
        _con.print(f"\n[bold]Generating report for case:[/bold] {case_id}")

        outputs = {}

        html_path = self._generate_html(report_data)
        if html_path:
            outputs["html"] = str(html_path)
            _con.print(f"[green]HTML report:[/green] {html_path}")

        text_path = self._generate_text(report_data)
        if text_path:
            outputs["text"] = str(text_path)
            _con.print(f"[green]Text report:[/green] {text_path}")

        json_path = self._generate_json(report_data)
        if json_path:
            outputs["json"] = str(json_path)
            _con.print(f"[green]JSON report:[/green] {json_path}")

        return outputs

    def build_report_data(
        self,
        case_id: str,
        firmware_findings: list,
        antiforensics_findings: list,
        timeline: list,
        attack_graph: dict,
        confidence: dict,
        analyst: str = "PTH Automated Analysis",
    ) -> dict:
        """
        Build the report data dict from all module outputs.
        This is what you pass into generate().
        """
        return {
            "case_id":               case_id,
            "analysis_date":         datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "analyst":               analyst,
            "firmware_findings":     firmware_findings,
            "antiforensics_findings": antiforensics_findings,
            "timeline":              self._serialize_timeline(timeline),
            "attack_graph":          attack_graph,
            "confidence":            confidence,
        }
    
    # HTML report

    def _generate_html(self, report_data: dict) -> Path | None:
        try:
            template = self.jinja_env.get_template("forensic_report.html")
            rendered = template.render(**report_data)

            output_path = self.output_dir / f"{report_data['case_id']}_report.html"
            output_path.write_text(rendered, encoding="utf-8")
            return output_path

        except Exception as e:
            _con.print(f"[red]HTML generation failed:[/red] {e}")
            return None
    
    # Plain text report

    def _generate_text(self, report_data: dict) -> Path | None:
        try:
            lines = []
            sep  = "=" * 65
            dash = "-" * 65

            lines.append(sep)
            lines.append("  PERSISTENT THREAT HUNTER - Forensic Analysis Report")
            lines.append(sep)
            lines.append("")
            lines.append(f"Case ID       : {report_data['case_id']}")
            lines.append(f"Analysis Date : {report_data['analysis_date']}")
            lines.append(f"Analyst       : {report_data['analyst']}")
            lines.append("")

            conf  = report_data.get("confidence", {})
            score = conf.get("confidence_score", 0)
            lines.append(f"Confidence Score : {score}%")
            lines.append(f"Verdict          : {conf.get('verdict', 'N/A')}")
            lines.append("")

            # Firmware findings
            lines.append(dash)
            lines.append("FIRMWARE ANALYSIS FINDINGS")
            lines.append(dash)
            fw = report_data.get("firmware_findings", [])
            if fw:
                for entry in fw:
                    for f in entry.get("findings", []):
                        lines.append(
                            f"[{f.get('severity','?')}] {f.get('type','?')} - {f.get('detail','')}"
                        )
                        if f.get("rootkit"):
                            lines.append(f"         Rootkit: {f['rootkit']}")
            else:
                lines.append("No firmware threats detected")
            lines.append("")

            # Anti-forensics findings
            lines.append(dash)
            lines.append("ANTI-FORENSICS DETECTION")
            lines.append(dash)
            af = report_data.get("antiforensics_findings", [])
            if af:
                for f in af:
                    lines.append(
                        f"[{f.get('severity','?')}] {f.get('type','?')} - {f.get('detail','')}"
                    )
                    if f.get("timestamp"):
                        lines.append(f"         Time: {f['timestamp']}")
            else:
                lines.append("No anti-forensics activity detected")
            lines.append("")

            # Timeline
            lines.append(dash)
            lines.append("RECONSTRUCTED ATTACK TIMELINE")
            lines.append(dash)
            for event in report_data.get("timeline", []):
                ts     = event.get("timestamp", "Unknown time")
                phase  = event.get("attack_phase", "unknown")
                ftype  = event.get("finding_type", "?")
                detail = event.get("detail", "")
                lines.append(f"{ts}  [{phase}]  {ftype} - {detail}")
            lines.append("")

            # Attack chain
            lines.append(dash)
            lines.append("ATTACK CHAIN")
            lines.append(dash)
            graph   = report_data.get("attack_graph", {})
            phases  = graph.get("active_phases", [])
            visible = [p for p in phases if p != "unknown"]
            if visible:
                lines.append(" ──→ ".join(
                    p.replace("_", " ").title() for p in visible
                ))
            else:
                lines.append("No attack chain detected")
            lines.append("")
            lines.append(sep)

            output_path = self.output_dir / f"{report_data['case_id']}_report.txt"
            output_path.write_text("\n".join(lines), encoding="utf-8")
            return output_path

        except Exception as e:
            _con.print(f"[red]Text generation failed:[/red] {e}")
            return None
        
    # JSON report - Machine readable

    def _generate_json(self, report_data: dict) -> Path | None:
        try:
            output_path = self.output_dir / f"{report_data['case_id']}_report.json"
            output_path.write_text(
                json.dumps(report_data, indent=2, default=str),
                encoding="utf-8"
            )
            return output_path
        except Exception as e:
            _con.print(f"[red]JSON generation failed:[/red] {e}")
            return None
        
    # Helper

    def _serialize_timeline(self, events: list) -> list:
        """Convert datetime objects to strings for template rendering"""
        serialized = []
        for e in events:
            entry = dict(e)
            if hasattr(entry.get("timestamp"), "isoformat"):
                entry["timestamp"] = entry["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC")
            serialized.append(entry)
        return serialized
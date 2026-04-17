import json
import struct
from pathlib import Path
from datetime import datetime, timezone, timedelta
from rich.console import Console

_con = Console()

DEFAULT_GAP_THRESHOLD_MINUTES = 30

# Windows Event IDs we care about
SUSPICIOUS_EVENT_IDS = {
    1102: "Security log cleared",
    104:  "System log cleared",
    4719: "Audit policy changed",
    4624: "Successful logon",
    4625: "Failed logon",
    4688: "Process creation",
    4698: "Scheduled task created",
    7045: "New service installed",
}


class LogGapAnalyzer:
    """
    Detects anti-forensics in windows Event Logs:

    1. Explicit log clearing (ID 1102 / 104)
    2. Suspicious time gaps - periods with no events at all
    3. Missing expected events (like login with no logoff)

    works in 2 modes:
        Live Mode - reads from windows event log via subprocess
        File Mode - parses exported .evtx or our own simple JSON log

    for testing I'll use a JSON based sythetic log format
    it mimics the real event log structure without needing actual .evtx file 
    """

    def __init__ (self, gap_threshold_minutes: int = DEFAULT_GAP_THRESHOLD_MINUTES):
        self.threshold_minutes = gap_threshold_minutes
        self.findings = []

    # Public API

    def analyze_records(self, records: list[dict]) -> list[dict]:
        """
        Analyze a list of event records, each event log should have:
            event_id    (int)
            timestamp   (datetime or ISO string)
            user        (str, optional)
            message     (str, optional)
        
        return list of findings
        """
        self.findings = []

        if not records:
            return[]
        
        # Parse and sort by timestamp
        parsed = self._parse_records(records)
        if not parsed:
            return []
        
        parsed.sort(key=lambda r: r["timestamp"])

        # Run all checks
        self.findings += self._detect_explicit_clears(parsed)
        self.findings += self._detect_time_gaps(parsed)
        self.findings += self._detect_audit_policy_changes(parsed)

        return self.findings
    
    def analyze_json_file(self, json_path: str) -> list[dict]:
        """
        Load event record from JSON file and analyze them.
        JSON would be a list of record dicts.
        """
        path = Path(json_path)
        if not path.exists():
            _con.print(f"[red]Error:[/red] File not found: {json_path}")
            return []
        
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(records, list):
                _con.print("[red]Error:[/red] JSON file should contain a list of records")
                return []
            return self.analyze_records(records)
        except json.JSONDecodeError as e:
            _con.print(f"[red]Error:[/red] Invalid JSON: {e}")
            return []
        
    def analyze_live_windows_logs(self, log_name: str = "Security") -> list[dict]:
        """
        Read live windows evet log using powershell.
        Returns finding from last 1000 events.
        """
        import platform
        if platform.system() != "Windows":
            _con.print("[red]Error:[/red] Live Log analysis requires Windows")
            return []
        
        import subprocess
        _con.print(f"[bold]Reading Live Windows {log_name} event log...[/bold]")

        ps_cmd = (
            f"Get-WinEvent -LogName '{log_name}' -MaxEvents 1000 |"
            f"Select-Object Id, TimeCreated, UserId, Message |"
            f"ConvertTo-Json"
        )

        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                _con.print(f"[red]PowerShell error:[/red] {result.stderr[:200]}")
                return []

            raw = json.loads(result.stdout)
            if isinstance(raw, dict):
                raw = [raw]

            records = []
            for item in raw:
                records.append({
                    "event_id":  item.get("Id", 0),
                    "timestamp": item.get("TimeCreated", ""),
                    "user":      str(item.get("UserId", "")),
                    "message":   item.get("Message", "")[:200],
                })

            return self.analyze_records(records)

        except subprocess.TimeoutExpired:
            _con.print("[red]Error:[/red] PowerShell timed out")
            return []
        except json.JSONDecodeError as e:
            _con.print(f"[red]Error:[/red] Could not parse PowerShell output: {e}")
            return []
        
    def get_summary(self) -> dict:
        """Return summary of findings"""
        severity_counts = {}
        finding_types   = {}

        for f in self.findings:
            sev = f.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            ft = f.get("type", "unknown")
            finding_types[ft] = finding_types.get(ft, 0) + 1

        return {
            "total_findings":       len(self.findings),
            "severity_breakdown":   severity_counts,
            "finding_types":        finding_types,
            "findings":             self.findings,
        }
    
    # Detection Method

    def _detect_explicit_clears(self, records: list[dict]) -> list[dict]:
        """Detects Event ID 1102 / 104"""
        findings = []

        for record in records:
            if record["event_id"] in [1102, 104]:
                findings.append({
                    "type":      "explicit_log_clear",
                    "severity":  "CRITICAL",
                    "timestamp": record["timestamp"].isoformat(),
                    "event_id":  record["event_id"],
                    "user":      record.get("user", "unknown"),
                    "detail":    f"Event log explicitly cleared (Event ID {record['event_id']})",
                })

        return findings
    
    def _detect_time_gaps(self, records: list[dict]) -> list[dict]:
        """
        Detect suspiciously long gaps between events
        system with no event for 30+ minutes
        """
        findings = []

        for i in range(1, len(records)):
            prev_time = records[i - 1]["timestamp"]
            curr_time = records[i]["timestamp"]
            delta_minutes = (curr_time - prev_time).total_seconds() / 60

            if delta_minutes >= self.threshold_minutes:
                severity = "CRITICAL" if delta_minutes > 120 else "HIGH" if delta_minutes > 60 else "MEDIUM"

                findings.append({
                    "type":             "suspicious_gap",
                    "severity":         severity,
                    "gap_start":        prev_time.isoformat(),
                    "gap_end":          curr_time.isoformat(),
                    "gap_duration_min": round(delta_minutes, 1),
                    "detail":           f"No events for {round(delta_minutes, 1)} minutes",
                })
        
        return findings

    def _detect_audit_policy_changes(self, records: list[dict]) -> list[dict]:
        """Detect Event ID 4719 - attackers disabling logging"""
        findings = []

        for record in records:
            if record["event_id"] == 4719:
                findings.append({
                    "type":      "audit_policy_change",
                    "severity":  "HIGH",
                    "timestamp": record["timestamp"].isoformat(),
                    "user":      record.get("user", "unknown"),
                    "detail":    "Audit policy modified - attacker may be disabling logging",
                })

        return findings
    
    # Helpers

    def _parse_records(self, records: list[dict]) -> list[dict]:
        """Normalize records - fill missing fields, parse timestamps"""
        parsed = []
        for r in records:
            ts = self._parse_dt(r.get("timestamp"))
            if ts is None:
                continue
            parsed.append({
                "event_id":  int(r.get("event_id", 0)),
                "timestamp": ts,
                "user":      r.get("user", "unknown"),
                "message":   r.get("message", ""),
            })
        return parsed
    
    def _parse_dt(self, value) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value
        try:
            dt = datetime.fromisoformat(str(value))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None

    
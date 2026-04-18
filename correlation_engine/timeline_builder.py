from datetime import datetime, timezone
from rich.console import Console

_con = Console()

# Attack phases based on MITRE ATT&CK for UEFI/firmware threats
ATTACK_PHASES = {
    "initial_access":    ["known_rootkit_indicator", "known_rootkit_hash"],
    "persistence":       ["unsigned_smm", "suspicious_smm_allocation", "tiny_smm_stub", "yara_match"],
    "defense_evasion":   ["explicit_log_clear", "suspicious_gap", "audit_policy_change"],
    "impact":            ["timestomp"],
}


class TimelineBuilder:
    """
    Takes raw finding from firmware and anti-forensic module
    then organizes them into a chronological attack order.

    Each event gets:
        1. normalize timestamp
        2. attack phase label
        3. source module tag
        4. severity level

    it is the foundation for the attack graph and report
    """

    def __init__(self):
        self.events = []

    # Public API

    def add_firmware_findings(self, findings: list[dict], base_timestamp: datetime = None):
        """
        Ingest findings from RootkitDetector.scan_all_drivers()
        firmware_findings is the 'flagged' list from that summary.
        """
        ts = base_timestamp or datetime.now(tz=timezone.utc)

        for driver_entry in findings:
            for finding in driver_entry.get("findings", []):
                event = self._build_event(
                    source="firmware",
                    finding_type=finding.get("type", "unknown"),
                    severity=finding.get("severity", "MEDIUM"),
                    detail=finding.get("detail", ""),
                    timestamp=finding.get("timestamp", ts),
                    extra={
                        "driver_guid":  driver_entry.get("guid", "unknown"),
                        "driver_offset": driver_entry.get("offset", 0),
                        "rootkit":      finding.get("rootkit", None),
                        "confidence":   finding.get("confidence", "MEDIUM"),
                    }
                )
                self.events.append(event)

    def add_antiforensics_findings(self, findings: list[dict]):
        """Ingest findings from TimestompDetector or LogGapAnalyzer"""
        for finding in findings:
            ts = finding.get("timestamp") or finding.get("gap_start")

            event = self._build_event(
                source="anti_forensics",
                finding_type=finding.get("type", "unknown"),
                severity=finding.get("severity", "MEDIUM"),
                detail=finding.get("detail", ""),
                timestamp=ts,
                extra={
                    "file_path":        finding.get("file_path", None),
                    "gap_duration_min": finding.get("gap_duration_min", None),
                    "event_id":         finding.get("event_id", None),
                    "user":             finding.get("user", None),
                }
            )
            self.events.append(event)

    def build(self) -> list[dict]:
        """
        Sort all events chronologically and assign attack phase labels
        then Returns the sorted timeline as a list of event dicts.
        """
        # Sort - put unknown timestamps at the end
        self.events.sort(key=lambda e: (
            e["timestamp"] is None,
            e["timestamp"] or datetime.max.replace(tzinfo=timezone.utc)
        ))

        # Assign phase labels
        for event in self.events:
            event["attack_phase"] = self._classify_phase(event["finding_type"])

        _con.print(f"[bold]Timeline built:[/bold] {len(self.events)} event(s)")
        self._print_summary()

        return self.events

    def get_events(self) -> list[dict]:
        return self.events

    def get_events_by_phase(self) -> dict:
        """Group events by attack phase"""
        phases = {phase: [] for phase in ATTACK_PHASES}
        phases["unknown"] = []

        for event in self.events:
            phase = event.get("attack_phase", "unknown")
            if phase in phases:
                phases[phase].append(event)
            else:
                phases["unknown"].append(event)

        return phases

    def get_events_by_severity(self, severity: str) -> list[dict]:
        """Filter events by severity level"""
        return [e for e in self.events if e.get("severity") == severity]

    def get_critical_events(self) -> list[dict]:
        return self.get_events_by_severity("CRITICAL")
    
    # Helpers

    def _build_event(
        self,
        source: str,
        finding_type: str,
        severity: str,
        detail: str,
        timestamp,
        extra: dict = None,
    ) -> dict:
        """Build a normalized timeline event"""
        return {
            "source":       source,
            "finding_type": finding_type,
            "severity":     severity,
            "detail":       detail,
            "timestamp":    self._parse_ts(timestamp),
            "attack_phase": None,   # Filled in by build()
            "extra":        extra or {},
        }

    def _classify_phase(self, finding_type: str) -> str:
        """Map a finding type to an ATT&CK phase"""
        for phase, types in ATTACK_PHASES.items():
            if finding_type in types:
                return phase
        # Fallback heuristics
        if "smm" in finding_type.lower():
            return "persistence"
        if "log" in finding_type.lower() or "gap" in finding_type.lower():
            return "defense_evasion"
        if "rootkit" in finding_type.lower():
            return "initial_access"
        return "unknown"

    def _parse_ts(self, value) -> datetime | None:
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

    def _print_summary(self):
        phases = self.get_events_by_phase()
        for phase, events in phases.items():
            if events:
                _con.print(f"  [cyan]{phase}[/cyan]: {len(events)} event(s)")
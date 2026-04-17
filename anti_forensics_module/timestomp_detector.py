import os
import stat
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from rich.console import Console

_con = Console()

# Timestomp threshold - if SI & FN differ by more then this flag it
DEFAULT_THRESHOLD_SECONDS = 3600 # 1 hr


class TimestompDetector:
    """
    Detects timestomping - the attacker technique of modifying the file's
    timestamps to hide when malware planted.

    As per real forensics compares $STANDARD_INFORMATION vs $FILE_NAME attributes
    in the NTFS MFT. We cant parse raw MFT on windows without a driver. so we use 
    these modes:

    Mode 1 - Live: Uses os.stat() to get filesystem timestamps.
                   Detects timestomping where mtime < ctime
                   or timestamps are suspiciously round numbers.

    Mode 2 - Batch: Scan a directory tree and scores each file.
    """

    def __init__(self, threshold_seconds: int = DEFAULT_THRESHOLD_SECONDS):
        self.threshold = threshold_seconds
        self.findings = []

    # Public API

    def analyze_file(self, file_path: str) -> dict | None:
        """
        Analyzing the single file for timestomp and then
        Returns a finding dict if suspicious
        """
        path = Path(file_path)

        if not path.exists():
            _con.print(f"[red]Error:[/red] File not find: {file_path}")
            return None
        
        try:
            st = path.stat()
        except (PermissionError, OSError) as e:
            _con.print(f"[yellow]Warning:[/yellow] Cannot stat {file_path}")
            return None
        
        ctime = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc)
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        atime = datetime.fromtimestamp(st.st_atime, tz=timezone.utc)

        indicators = []

        # check 1: mtime is earlier than ctime
        # on NTFS, ctime = metadata change time. if mtime < ctime by a lot,
        # someone mayhave backdated the modification time.
        delta_mc = (ctime - mtime).total_seconds()
        if delta_mc > self.threshold:
            indicators.append({
                "check":    "mtime_before_ctime",
                "detail":   f"mtime is {self._fmt_delta(delta_mc)} before ctime",
                "delta_s":  delta_mc,
            })

        # check 2: suspiciously round timestamps
        # Attcakers often set timestampsto exact midnight 00:00:00
        # Real files rarely have perfectly zero seconds and minutes
        if self._is_round_timestamp(mtime):
            indicators.append({
                "check":    "round_mtime",
                "detail":  f"mtime is suspiciously round: {mtime.isoformat()}",
                "delta_s":  0,
            })

        # check 3: timestamp in future
        now = datetime.now(tz=timezone.utc)
        if mtime > now:
            indicators.append({
                "check":    "future_mtime",
                "detail":   f"mtime is the future: {mtime.isoformat()}",
                "delta_s":  (mtime - now).total_seconds(),
            })
    
        # check 4: atime earlier than mtime (file accessed before it was modified)
        if atime < mtime:
            delta_am = (mtime - atime).total_seconds()
            if delta_am > self.threshold:
                indicators.append({
                    "check":    "atime_before_mtime",
                    "detail":   f"atime is {self._fmt_delta(delta_am)} before mtime",
                    "delta_s":  delta_am,
                })
        
        if not indicators:
            return None
        
        severity = self._calculate_severity(indicators)

        finding = {
            "file_path":        str(path.resolve()),
            "file_size":        st.st_size,
            "ctime":            ctime.isoformat(),
            "mtime":            mtime.isoformat(),
            "atime":            atime.isoformat(),
            "indicators":       indicators,
            "severity":         severity,
            "indicator_count":  len(indicators),
        }

        self.findings.append(findings)
        return findings
    
    def scan_directory(self, directory: str, recursive: bool = True) -> list[dict]:
        """
        scan all files in directory for timestomp indicators.
        returns a list of findings
        """
        base = Path(directory)

        if not base.exists():
            _con.print(f"[red]Error:[/red] Directory not found: {directory}")
            return []
        
        self.findings = []
        pattern = "**/*" if recursive else "*"
        files = [f for f in base.glob(pattern) if f.is_file()]

        _con.print(f"[bold]Scanning {len(files)} files in {directory}...[/bold]")

        for file_path in files:
            self.analyze_file(str(file_path))

        _con.print(
            f"[bold]Scan completed:[/bold]"
            f"[red]{len(self.findings)}[/red] suspicious file(s) found"
        )

        return self.findings
    
    def analyze_timestamp_list(self, records: list[dict]) -> list[dict]:
        """
        Analyze a list of pre-extracted timestamp records.
        Used when you have MFT data from an external tool

        each record should have:
            file_path, si_create, si_modify, fn_create, fn_modify

        this is a proper FORENSICS method - comparing SI vs FN attributes.
        """
        findings = []

        for record in records:
            si_create = self._parse_dt(record.get("si_create"))
            fn_create = self._parse_dt(record.get("fn_create"))
            si_modify = self._parse_dt(record.get("si_modify"))
            fn_modify = self._parse_dt(record.get("fn_modify"))

            indicators = []

            if si_create and fn_create:
                delta = abs((si_create - fn_create).total_seconds())
                if delta > self.threshold:
                    indicators.append({
                        "check":    "si_fn_create_mismatach",
                        "detail":   f"$SI create differ from $FN create by {self._fmt_delta(delta)}",
                        "delta_s":  delta,
                    })
            
            if si_modify and fn_modify:
                delta = abs((si_modify - fn_modify).total_seconds())
                if delta > self.threshold:
                    indicators.append({
                        "check":    "si_fn_modify_mismatach",
                        "detail":   f"$SI modify differs from $FN modify by {self._fmt_delta(delta)}",
                        "delta_s":  delta,
                    })
            
            if indicators:
                findings.append({
                    "file_path":       record.get("file_path", "unknown"),
                    "indicators":      indicators,
                    "severity":        self._calculate_severity(indicators),
                    "indicator_count": len(indicators),
                    "si_create":       si_create.isoformat() if si_create else None,
                    "fn_create":       fn_create.isoformat() if fn_create else None,
                })

        return findings 

    def get_summary(self) -> dict:
        """Return summary of findings from last scan"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        return {
            "total_findings":       len(self.findings),
            "severity_breakdown":   severity_counts,
            "findings":             self.findings
        }
    
    # Helpers

    def _is_round_timestamp(self, dt: datetime) -> bool:
        """check if timestamp look suspiciously round"""
        return dt.second == 0 and dt.minute == 0 and dt.microsecond == 0
    
    def _calculate_severity(self, indicators: list[dict]) -> str:
        if len(indicators) >= 3:
            return "CRITICAL"
        max_delta = max((i.get("delta_s", 0) for i in indicators), default=0)
        if max_delta > 86400 * 7:   # More than 1 week off
            return "CRITICAL"
        if max_delta > 86400:       # More than 1 day off
            return "HIGH"
        if max_delta > 3600:        # More than 1 hour off
            return "MEDIUM"
        return "LOW"   

    def _fmt_delta(self, seconds: float) -> str:
        """Format a time delta into human readable format""" 
        td = timedelta(seconds=abs(seconds))
        days = td.days
        hours, remainder = divmod(td.seconds, 3600)
        minutes, secs = divmod(remainder, 60)

        if days > 0:
            return f"{days}d {hours}h"
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m {secs}s"

    def _parse_dt(self, value) -> datetime | None:
        """Parse a datetime from either a datetime object or ISO"""
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


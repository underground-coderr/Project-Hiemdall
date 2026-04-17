import pytest
from datetime import datetime, timezone, timedelta
from anti_forensics_module.timestomp_detector import TimestompDetector
from anti_forensics_module.log_gap_analyzer import LogGapAnalyzer


def make_dt(year, month, day, hour=0, minute=0, second=0):
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)

# TimestompDetector test

class TestTimestompDetector:

    @pytest.fixture
    def detector(self):
        return TimestompDetector(threshold_seconds=3600)

    def test_init_default_threshold(self):
        d = TimestompDetector()
        assert d.threshold == 3600

    def test_init_custom_threshold(self):
        d = TimestompDetector(threshold_seconds=7200)
        assert d.threshold == 7200

    def test_analyze_nonexistent_file(self, detector):
        result = detector.analyze_file("C:/does/not/exist.bin")
        assert result is None

    def test_analyze_real_file_no_crash(self, detector, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = detector.analyze_file(str(f))
        # May or may not find indicators - just should not crash

    def test_round_timestamp_detected(self, detector):
        dt = make_dt(2024, 1, 15, 0, 0, 0)
        assert detector._is_round_timestamp(dt) is True

    def test_non_round_timestamp_ok(self, detector):
        dt = make_dt(2024, 1, 15, 14, 32, 47)
        assert detector._is_round_timestamp(dt) is False

    def test_severity_critical_on_many_indicators(self, detector):
        indicators = [
            {"check": "a", "delta_s": 100},
            {"check": "b", "delta_s": 100},
            {"check": "c", "delta_s": 100},
        ]
        assert detector._calculate_severity(indicators) == "CRITICAL"

    def test_severity_critical_on_large_delta(self, detector):
        indicators = [{"check": "a", "delta_s": 86400 * 10}]
        assert detector._calculate_severity(indicators) == "CRITICAL"

    def test_severity_high_on_day_delta(self, detector):
        indicators = [{"check": "a", "delta_s": 86400 * 2}]
        assert detector._calculate_severity(indicators) == "HIGH"

    def test_severity_medium_on_hour_delta(self, detector):
        indicators = [{"check": "a", "delta_s": 7200}]
        assert detector._calculate_severity(indicators) == "MEDIUM"

    def test_fmt_delta_days(self, detector):
        result = detector._fmt_delta(86400 * 3)
        assert "d" in result

    def test_fmt_delta_hours(self, detector):
        result = detector._fmt_delta(7200)
        assert "h" in result

    def test_analyze_mft_records_clean(self, detector):
        records = [
            {
                "file_path": "C:/Windows/test.dll",
                "si_create": make_dt(2024, 1, 15, 10, 30, 0),
                "fn_create": make_dt(2024, 1, 15, 10, 30, 5),
                "si_modify": make_dt(2024, 1, 15, 11, 0, 0),
                "fn_modify": make_dt(2024, 1, 15, 11, 0, 5),
            }
        ]
        findings = detector.analyze_timestamp_list(records)
        assert findings == []

    def test_analyze_mft_records_timestomped(self, detector):
        records = [
            {
                "file_path": "C:/Windows/malicious.sys",
                "si_create": make_dt(2024, 1, 15, 3, 0, 0),
                "fn_create": make_dt(2026, 4, 1, 22, 47, 13),
                "si_modify": make_dt(2024, 1, 15, 3, 0, 0),
                "fn_modify": make_dt(2026, 4, 1, 22, 47, 13),
            }
        ]
        findings = detector.analyze_timestamp_list(records)
        assert len(findings) >= 1
        assert findings[0]["file_path"] == "C:/Windows/malicious.sys"

    def test_get_summary_structure(self, detector):
        summary = detector.get_summary()
        assert "total_findings" in summary
        assert "severity_breakdown" in summary
        assert "findings" in summary

# LogGapAnalyzer test

class TestLogGapAnalyzer:

    @pytest.fixture
    def analyzer(self):
        return LogGapAnalyzer(gap_threshold_minutes=30)

    def make_records(self, event_ids_and_times):
        """Helper to build event records from (event_id, datetime) tuples"""
        return [
            {
                "event_id":  eid,
                "timestamp": ts.isoformat(),
                "user":      "SYSTEM",
                "message":   f"Event {eid}",
            }
            for eid, ts in event_ids_and_times
        ]

    def test_empty_records_no_findings(self, analyzer):
        findings = analyzer.analyze_records([])
        assert findings == []

    def test_detects_explicit_log_clear_1102(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 22, 0, 0)),
            (1102, make_dt(2026, 4, 1, 23, 15, 0)),
            (4624, make_dt(2026, 4, 1, 23, 16, 0)),
        ])
        findings = analyzer.analyze_records(records)
        types = [f["type"] for f in findings]
        assert "explicit_log_clear" in types

    def test_detects_explicit_log_clear_104(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 22, 0, 0)),
            (104,  make_dt(2026, 4, 1, 23, 15, 0)),
        ])
        findings = analyzer.analyze_records(records)
        types = [f["type"] for f in findings]
        assert "explicit_log_clear" in types

    def test_log_clear_is_critical(self, analyzer):
        records = self.make_records([
            (1102, make_dt(2026, 4, 1, 23, 15, 0)),
        ])
        findings = analyzer.analyze_records(records)
        clears = [f for f in findings if f["type"] == "explicit_log_clear"]
        assert all(f["severity"] == "CRITICAL" for f in clears)

    def test_detects_time_gap(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 22, 0, 0)),
            (4624, make_dt(2026, 4, 1, 23, 30, 0)),  # 90 min gap
        ])
        findings = analyzer.analyze_records(records)
        types = [f["type"] for f in findings]
        assert "suspicious_gap" in types

    def test_small_gap_not_flagged(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 22, 0, 0)),
            (4624, make_dt(2026, 4, 1, 22, 10, 0)),  # 10 min — fine
        ])
        findings = analyzer.analyze_records(records)
        gaps = [f for f in findings if f["type"] == "suspicious_gap"]
        assert gaps == []

    def test_gap_severity_critical_over_120_min(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 20, 0, 0)),
            (4624, make_dt(2026, 4, 1, 23, 0, 0)),  # 180 min gap
        ])
        findings = analyzer.analyze_records(records)
        gaps = [f for f in findings if f["type"] == "suspicious_gap"]
        assert any(f["severity"] == "CRITICAL" for f in gaps)

    def test_detects_audit_policy_change(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 22, 0, 0)),
            (4719, make_dt(2026, 4, 1, 22, 5, 0)),
        ])
        findings = analyzer.analyze_records(records)
        types = [f["type"] for f in findings]
        assert "audit_policy_change" in types

    def test_clean_log_no_findings(self, analyzer):
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 9,  0, 0)),
            (4624, make_dt(2026, 4, 1, 9, 15, 0)),
            (4624, make_dt(2026, 4, 1, 9, 30, 0)),
            (4624, make_dt(2026, 4, 1, 9, 45, 0)),
        ])
        findings = analyzer.analyze_records(records)
        assert findings == []

    def test_records_sorted_by_timestamp(self, analyzer):
        # Feed records out of order - should still detect gap correctly
        records = self.make_records([
            (4624, make_dt(2026, 4, 1, 23, 30, 0)),
            (4624, make_dt(2026, 4, 1, 22,  0, 0)),
        ])
        findings = analyzer.analyze_records(records)
        gaps = [f for f in findings if f["type"] == "suspicious_gap"]
        assert len(gaps) == 1
        assert gaps[0]["gap_duration_min"] == 90.0

    def test_get_summary_structure(self, analyzer):
        summary = analyzer.get_summary()
        assert "total_findings" in summary
        assert "severity_breakdown" in summary
        assert "finding_types" in summary
        assert "findings" in summary
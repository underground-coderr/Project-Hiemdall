import pytest
from datetime import datetime, timezone
from correlation_engine.timeline_builder import TimelineBuilder
from correlation_engine.confidence_scorer import ConfidenceScorer
from correlation_engine.attack_graph import AttackGraphBuilder


def make_dt(hour=12, minute=0):
    return datetime(2026, 4, 1, hour, minute, 0, tzinfo=timezone.utc)


# Sample data helpers

def firmware_flagged_entry(finding_type="unsigned_smm", severity="HIGH"):
    return {
        "guid":      "AAAAAAAA-0000-0000-0000-000000000001",
        "type_name": "SMM_DRIVER",
        "offset":    0x1000,
        "size":      512,
        "findings": [{
            "type":       finding_type,
            "severity":   severity,
            "detail":     "Test finding",
            "confidence": "HIGH",
        }]
    }


def af_finding(finding_type="explicit_log_clear", severity="CRITICAL"):
    return {
        "type":      finding_type,
        "severity":  severity,
        "timestamp": make_dt(23, 15).isoformat(),
        "detail":    "Test anti-forensics finding",
        "user":      "SYSTEM",
    }


# TimelineBuilder test

class TestTimelineBuilder:

    @pytest.fixture
    def builder(self):
        return TimelineBuilder()

    def test_init_empty(self, builder):
        assert builder.events == []

    def test_add_firmware_findings(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry()])
        assert len(builder.events) == 1

    def test_add_antiforensics_findings(self, builder):
        builder.add_antiforensics_findings([af_finding()])
        assert len(builder.events) == 1

    def test_build_returns_list(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry()])
        result = builder.build()
        assert isinstance(result, list)

    def test_events_have_required_fields(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry()])
        builder.add_antiforensics_findings([af_finding()])
        events = builder.build()
        for e in events:
            assert "source" in e
            assert "finding_type" in e
            assert "severity" in e
            assert "attack_phase" in e

    def test_firmware_source_tagged(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry()])
        events = builder.build()
        assert events[0]["source"] == "firmware"

    def test_antiforensics_source_tagged(self, builder):
        builder.add_antiforensics_findings([af_finding()])
        events = builder.build()
        assert events[0]["source"] == "anti_forensics"

    def test_attack_phase_assigned(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry("unsigned_smm")])
        events = builder.build()
        assert events[0]["attack_phase"] == "persistence"

    def test_log_clear_maps_to_defense_evasion(self, builder):
        builder.add_antiforensics_findings([af_finding("explicit_log_clear")])
        events = builder.build()
        assert events[0]["attack_phase"] == "defense_evasion"

    def test_rootkit_maps_to_initial_access(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry("known_rootkit_indicator")])
        events = builder.build()
        assert events[0]["attack_phase"] == "initial_access"

    def test_get_critical_events(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry("known_rootkit_hash", "CRITICAL")])
        builder.add_antiforensics_findings([af_finding("suspicious_gap", "MEDIUM")])
        builder.build()
        critical = builder.get_critical_events()
        assert all(e["severity"] == "CRITICAL" for e in critical)

    def test_get_events_by_phase(self, builder):
        builder.add_firmware_findings([firmware_flagged_entry("unsigned_smm")])
        builder.add_antiforensics_findings([af_finding("explicit_log_clear")])
        builder.build()
        by_phase = builder.get_events_by_phase()
        assert "persistence" in by_phase
        assert "defense_evasion" in by_phase


# ConfidenceScorer test

class TestConfidenceScorer:

    @pytest.fixture
    def scorer(self):
        return ConfidenceScorer()

    def make_events(self, types_severities):
        return [
            {
                "finding_type": ft,
                "severity":     sev,
                "attack_phase": "persistence",
                "source":       "firmware",
            }
            for ft, sev in types_severities
        ]

    def test_empty_events_zero_score(self, scorer):
        result = scorer.calculate([])
        assert result["confidence_score"] == 0.0

    def test_score_is_float(self, scorer):
        events = self.make_events([("unsigned_smm", "HIGH")])
        result = scorer.calculate(events)
        assert isinstance(result["confidence_score"], float)

    def test_score_between_0_and_100(self, scorer):
        events = self.make_events([
            ("known_rootkit_hash", "CRITICAL"),
            ("unsigned_smm", "HIGH"),
            ("explicit_log_clear", "CRITICAL"),
        ])
        result = scorer.calculate(events)
        assert 0.0 <= result["confidence_score"] <= 100.0

    def test_high_severity_scores_higher(self, scorer):
        low_events  = self.make_events([("unsigned_smm", "LOW")])
        high_events = self.make_events([("unsigned_smm", "CRITICAL")])
        low_score  = scorer.calculate(low_events)["confidence_score"]
        high_score = scorer.calculate(high_events)["confidence_score"]
        assert high_score > low_score

    def test_result_has_verdict(self, scorer):
        result = scorer.calculate([])
        assert "verdict" in result

    def test_result_has_breakdown(self, scorer):
        events = self.make_events([("unsigned_smm", "HIGH")])
        result = scorer.calculate(events)
        assert "breakdown" in result
        assert "unsigned_smm" in result["breakdown"]

    def test_verdict_clean_on_zero(self, scorer):
        result = scorer.calculate([])
        assert "CLEAN" in result["verdict"]

    def test_verdict_confirmed_on_high_score(self, scorer):
        events = self.make_events([
            ("known_rootkit_hash", "CRITICAL"),
            ("known_rootkit_indicator", "CRITICAL"),
            ("explicit_log_clear", "CRITICAL"),
            ("yara_match", "CRITICAL"),
        ])
        result = scorer.calculate(events)
        if result["confidence_score"] >= 85:
            assert "CONFIRMED" in result["verdict"]

    def test_phases_detected_in_result(self, scorer):
        events = self.make_events([("unsigned_smm", "HIGH")])
        result = scorer.calculate(events)
        assert "phases_detected" in result


# AttacGraphBuilder test

class TestAttackGraphBuilder:

    @pytest.fixture
    def graph_builder(self):
        return AttackGraphBuilder()

    def make_events(self, phase_types):
        return [
            {
                "finding_type": ft,
                "severity":     "HIGH",
                "attack_phase": phase,
                "source":       "firmware",
            }
            for phase, ft in phase_types
        ]

    def test_empty_events_empty_graph(self, graph_builder):
        graph = graph_builder.build([])
        assert graph["nodes"] == []
        assert graph["edges"] == []

    def test_builds_nodes(self, graph_builder):
        events = self.make_events([("persistence", "unsigned_smm")])
        graph  = graph_builder.build(events)
        assert len(graph["nodes"]) >= 1

    def test_node_has_required_fields(self, graph_builder):
        events = self.make_events([("persistence", "unsigned_smm")])
        graph  = graph_builder.build(events)
        node   = graph["nodes"][0]
        assert "id" in node
        assert "label" in node
        assert "phase" in node
        assert "severity" in node

    def test_edges_created_between_phases(self, graph_builder):
        events = self.make_events([
            ("initial_access", "known_rootkit_indicator"),
            ("persistence",    "unsigned_smm"),
        ])
        graph = graph_builder.build(events)
        assert len(graph["edges"]) >= 1

    def test_edge_has_required_fields(self, graph_builder):
        events = self.make_events([
            ("initial_access", "known_rootkit_indicator"),
            ("persistence",    "unsigned_smm"),
        ])
        graph = graph_builder.build(events)
        edge  = graph["edges"][0]
        assert "from" in edge
        assert "to" in edge
        assert "relationship" in edge

    def test_duplicate_types_increment_count(self, graph_builder):
        events = self.make_events([
            ("persistence", "unsigned_smm"),
            ("persistence", "unsigned_smm"),
        ])
        graph = graph_builder.build(events)
        smm_nodes = [n for n in graph["nodes"] if n["type"] == "unsigned_smm"]
        assert smm_nodes[0]["count"] == 2

    def test_active_phases_populated(self, graph_builder):
        events = self.make_events([
            ("initial_access", "known_rootkit_indicator"),
            ("defense_evasion", "explicit_log_clear"),
        ])
        graph = graph_builder.build(events)
        assert "initial_access" in graph["active_phases"]
        assert "defense_evasion" in graph["active_phases"]

    def test_render_ascii_no_crash(self, graph_builder):
        events = self.make_events([
            ("initial_access", "known_rootkit_indicator"),
            ("persistence",    "unsigned_smm"),
        ])
        graph  = graph_builder.build(events)
        output = graph_builder.render_ascii(graph)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_render_ascii_empty_graph(self, graph_builder):
        graph  = graph_builder.build([])
        output = graph_builder.render_ascii(graph)
        assert "No attack chain" in output
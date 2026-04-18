import pytest
from pathlib import Path
from reporting.report_generator import ReportGenerator


@pytest.fixture
def generator(tmp_path):
    return ReportGenerator(output_dir=str(tmp_path))


@pytest.fixture
def sample_report_data(generator):
    return generator.build_report_data(
        case_id="PTH-TEST-001",
        firmware_findings=[
            {
                "guid": "AAAA-0000",
                "findings": [
                    {
                        "type":     "unsigned_smm",
                        "severity": "HIGH",
                        "detail":   "SMM driver lacks WinCert signature",
                        "rootkit":  None,
                    }
                ]
            }
        ],
        antiforensics_findings=[
            {
                "type":      "explicit_log_clear",
                "severity":  "CRITICAL",
                "detail":    "Event log cleared",
                "timestamp": "2026-04-01 23:15:00 UTC",
            }
        ],
        timeline=[
            {
                "source":       "firmware",
                "finding_type": "unsigned_smm",
                "severity":     "HIGH",
                "detail":       "SMM driver lacks WinCert signature",
                "timestamp":    None,
                "attack_phase": "persistence",
                "extra":        {},
            }
        ],
        attack_graph={
            "nodes": [
                {
                    "id":       0,
                    "type":     "unsigned_smm",
                    "label":    "Unsigned SMM Driver",
                    "phase":    "persistence",
                    "severity": "HIGH",
                    "count":    1,
                }
            ],
            "edges":         [],
            "phase_summary": {"persistence": 1},
            "active_phases": ["persistence"],
        },
        confidence={
            "confidence_score": 72.5,
            "verdict":          "HIGH PROBABILITY - Strong indicators of compromise",
            "phases_detected":  ["persistence"],
            "breakdown": {
                "unsigned_smm": {
                    "count":        1,
                    "total_weight": 0.715,
                    "severity":     "HIGH",
                }
            },
            "finding_count": 1,
        },
    )


# build_report_data test

def test_build_report_data_structure(sample_report_data):
    assert "case_id" in sample_report_data
    assert "analysis_date" in sample_report_data
    assert "analyst" in sample_report_data
    assert "firmware_findings" in sample_report_data
    assert "antiforensics_findings" in sample_report_data
    assert "timeline" in sample_report_data
    assert "attack_graph" in sample_report_data
    assert "confidence" in sample_report_data


def test_case_id_preserved(sample_report_data):
    assert sample_report_data["case_id"] == "PTH-TEST-001"


def test_analysis_date_set(sample_report_data):
    assert "UTC" in sample_report_data["analysis_date"]

# HTML generation test

def test_generates_html_file(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    assert "html" in outputs
    assert Path(outputs["html"]).exists()


def test_html_contains_case_id(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["html"]).read_text(encoding="utf-8")
    assert "PTH-TEST-001" in content


def test_html_contains_score(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["html"]).read_text(encoding="utf-8")
    assert "72.5" in content


def test_html_contains_finding(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["html"]).read_text(encoding="utf-8")
    assert "unsigned_smm" in content

# Text generation test

def test_generates_text_file(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    assert "text" in outputs
    assert Path(outputs["text"]).exists()


def test_text_contains_case_id(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["text"]).read_text(encoding="utf-8")
    assert "PTH-TEST-001" in content


def test_text_contains_score(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["text"]).read_text(encoding="utf-8")
    assert "72.5" in content


def test_text_contains_verdict(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["text"]).read_text(encoding="utf-8")
    assert "HIGH PROBABILITY" in content

# JSON generation test

def test_generates_json_file(generator, sample_report_data, tmp_path):
    outputs = generator.generate(sample_report_data)
    assert "json" in outputs
    assert Path(outputs["json"]).exists()


def test_json_is_valid(generator, sample_report_data, tmp_path):
    import json
    outputs = generator.generate(sample_report_data)
    content = Path(outputs["json"]).read_text(encoding="utf-8")
    data    = json.loads(content)
    assert data["case_id"] == "PTH-TEST-001"

# Edge cases

def test_empty_findings_no_crash(generator, tmp_path):
    data = generator.build_report_data(
        case_id="PTH-EMPTY-001",
        firmware_findings=[],
        antiforensics_findings=[],
        timeline=[],
        attack_graph={"nodes": [], "edges": [], "phase_summary": {}, "active_phases": []},
        confidence={"confidence_score": 0.0, "verdict": "CLEAN", "phases_detected": [], "breakdown": {}, "finding_count": 0},
    )
    outputs = generator.generate(data)
    assert "html" in outputs
    assert "text" in outputs
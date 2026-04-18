from rich.console import Console

_con = Console()

# Weight of each findings type toward overall confidence score
FINDING_WEIGHTS = {
    # Firmware findings
    "known_rootkit_hash":       0.95,
    "known_rootkit_indicator":  0.85,
    "yara_match":               0.80,
    "unsigned_smm":             0.65,
    "suspicious_smm_allocation": 0.60,
    "tiny_smm_stub":            0.40,

    # Anti-forensics findings
    "explicit_log_clear":       0.85,
    "audit_policy_change":      0.70,
    "suspicious_gap":           0.55,
    "timestomp":                0.60,
    "si_fn_create_mismatch":    0.65,
    "si_fn_modify_mismatch":    0.60,

    # Default for unknown types
    "_default":                 0.30,
}

# Bonus multipliers when multiple phases are present
MULTI_PHASE_BONUS = {
    2: 1.10,   # Two phases seen - 10% boost
    3: 1.25,   # Three phases - 25% boost
    4: 1.40,   # All four phases - 40% boost
}

SEVERITY_MULTIPLIERS = {
    "CRITICAL": 1.20,
    "HIGH":     1.10,
    "MEDIUM":   1.00,
    "LOW":      0.80,
}


class ConfidenceScorer:
    """
    Calculate an overall confidence score (0-100) that a persistent
    threat is present, based on all timeline events.

    Higher score = more confident an attacker was active.

    scoring logic:
        1. Each finding contributes a base weight
        2. Severity multiplier applied per finding
        3. Multi-phase bonus if findings span multiple ATT&CK phases
        4. Score normalize to 0-100
    """

    def __init__(self):
        self.score = 0.0
        self.breakdown = {}

    def calculate(self, events: list[dict]) -> dict:
        """
        Calculate confidence score from timeline events
        then returns a result dict with score, breakdown, and verdict.
        """
        if not events:
            return self._build_result(0.0, {}, set())

        raw_score    = 0.0
        max_possible = 0.0
        breakdown    = {}
        phases_seen  = set()

        for event in events:
            finding_type = event.get("finding_type", "unknown")
            severity     = event.get("severity", "MEDIUM")
            phase        = event.get("attack_phase", "unknown")

            weight = FINDING_WEIGHTS.get(finding_type, FINDING_WEIGHTS["_default"])
            multiplier = SEVERITY_MULTIPLIERS.get(severity, 1.0)
            contribution = weight * multiplier

            raw_score    += contribution
            max_possible += 1.0     # Max weight per event is 1.0

            phases_seen.add(phase)

            if finding_type not in breakdown:
                breakdown[finding_type] = {
                    "count":        0,
                    "total_weight": 0.0,
                    "severity":     severity,
                }
            breakdown[finding_type]["count"]        += 1
            breakdown[finding_type]["total_weight"] += contribution

        # Normalize to 0-100
        base_score = (raw_score / max(max_possible, 1)) * 100

        # Apply multi-phase bonus
        phase_count   = len(phases_seen - {"unknown"})
        phase_bonus   = MULTI_PHASE_BONUS.get(phase_count, 1.0)
        final_score   = min(base_score * phase_bonus, 100.0)

        self.score     = round(final_score, 1)
        self.breakdown = breakdown

        result = self._build_result(self.score, breakdown, phases_seen)
        self._print_result(result)
        return result

    def _build_result(self, score: float, breakdown: dict, phases_seen: set) -> dict:
        return {
            "confidence_score": score,
            "verdict":          self._verdict(score),
            "phases_detected":  list(phases_seen),
            "breakdown":        breakdown,
            "finding_count":    sum(v["count"] for v in breakdown.values()),
        }

    def _verdict(self, score: float) -> str:
        if score >= 85:
            return "CONFIRMED THREAT - Immediate action required"
        if score >= 65:
            return "HIGH PROBABILITY - Strong indicators of compromise"
        if score >= 40:
            return "SUSPICIOUS - Further investigation recommended"
        if score >= 20:
            return "LOW SUSPICION - Anomalies detected, monitor closely"
        return "CLEAN - No significant indicators found"

    def _print_result(self, result: dict):
        score   = result["confidence_score"]
        verdict = result["verdict"]
        color   = "red" if score >= 65 else "yellow" if score >= 40 else "green"

        _con.print(f"\n[bold]Confidence Score:[/bold] [{color}]{score}%[/{color}]")
        _con.print(f"[bold]Verdict:[/bold] {verdict}")
        _con.print(f"[bold]Phases detected:[/bold] {', '.join(result['phases_detected'])}")
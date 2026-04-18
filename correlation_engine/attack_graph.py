from rich.console import Console

_con = Console()

# Maps finding types to node labels for the attack graph
NODE_LABELS = {
    "known_rootkit_hash":        "Rootkit Hash Match",
    "known_rootkit_indicator":   "Rootkit Indicator",
    "yara_match":                "YARA Rule Hit",
    "unsigned_smm":              "Unsigned SMM Driver",
    "suspicious_smm_allocation": "SMM Memory Abuse",
    "explicit_log_clear":        "Log Cleared",
    "suspicious_gap":            "Log Gap",
    "audit_policy_change":       "Audit Policy Modified",
    "timestomp":                 "Timestomping",
    "si_fn_create_mismatch":     "MFT Timestamp Tampered",
}

PHASE_ORDER = [
    "initial_access",
    "persistence",
    "defense_evasion",
    "impact",
    "unknown",
]


class AttackGraphBuilder:
    """
    Builds a simple attack graph form timeline events

    producing a structured dict that represents nodes
    and edges, which the report generator can render.

    Nodes = unique finding
    Edges = phases to phase progression
    """

    def __init__(self):
        self.nodes = []
        self.edges = []

    def build(self, events: list[dict]) -> dict:
        """
        Building an attack graph then returns graph
        dict with nodes, edges, and phase chains.
        """
        self.nodes = []
        self.edges = []

        if not events:
            return self._empty_graph()

        # Group events by phase
        phase_groups = {phase: [] for phase in PHASE_ORDER}
        for event in events:
            phase = event.get("attack_phase", "unknown")
            if phase in phase_groups:
                phase_groups[phase].append(event)
            else:
                phase_groups["unknown"].append(event)

        # Build nodes - one per unique finding type
        seen_types = set()
        node_id    = 0
        for phase in PHASE_ORDER:
            for event in phase_groups[phase]:
                ft = event.get("finding_type", "unknown")
                if ft not in seen_types:
                    seen_types.add(ft)
                    self.nodes.append({
                        "id":       node_id,
                        "type":     ft,
                        "label":    NODE_LABELS.get(ft, ft.replace("_", " ").title()),
                        "phase":    phase,
                        "severity": event.get("severity", "MEDIUM"),
                        "count":    1,
                    })
                    node_id += 1
                else:
                    # Increment count on existing node
                    for n in self.nodes:
                        if n["type"] == ft:
                            n["count"] += 1

        # Build edges - connect phases sequentially
        active_phases = [
            p for p in PHASE_ORDER
            if phase_groups[p]
        ]

        for i in range(len(active_phases) - 1):
            src_phase = active_phases[i]
            dst_phase = active_phases[i + 1]

            src_nodes = [n for n in self.nodes if n["phase"] == src_phase]
            dst_nodes = [n for n in self.nodes if n["phase"] == dst_phase]

            for src in src_nodes:
                for dst in dst_nodes:
                    self.edges.append({
                        "from":         src["id"],
                        "to":           dst["id"],
                        "from_phase":   src_phase,
                        "to_phase":     dst_phase,
                        "relationship": "leads_to",
                    })

        graph = {
            "nodes":         self.nodes,
            "edges":         self.edges,
            "phase_summary": {
                phase: len(events)
                for phase, events in phase_groups.items()
                if events
            },
            "active_phases": active_phases,
        }

        self._print_graph(graph)
        return graph

    def render_ascii(self, graph: dict) -> str:
        """Reders a simple ASCII representation of the attack chain."""
        active = graph.get("active_phases", [])
        if not active:
            return "No attack chain detected"

        parts = []
        for phase in active:
            if phase == "unknown":
                continue
            label = phase.replace("_", " ").title()
            nodes = [n for n in graph["nodes"] if n["phase"] == phase]
            node_labels = ", ".join(n["label"] for n in nodes)
            parts.append(f"[{label}]\n  └─ {node_labels}")

        return "\n      ↓\n".join(parts)

    def _empty_graph(self) -> dict:
        return {
            "nodes":         [],
            "edges":         [],
            "phase_summary": {},
            "active_phases": [],
        }

    def _print_graph(self, graph: dict):
        _con.print(f"\n[bold]Attack Graph:[/bold] {len(graph['nodes'])} node(s), {len(graph['edges'])} edge(s)")
        for phase in graph["active_phases"]:
            nodes = [n for n in graph["nodes"] if n["phase"] == phase]
            labels = " → ".join(n["label"] for n in nodes)
            _con.print(f"  [cyan]{phase}[/cyan]: {labels}")
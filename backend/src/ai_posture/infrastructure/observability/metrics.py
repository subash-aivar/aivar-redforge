"""Prometheus-style metrics collectors for M31 Phase 5."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class M31MetricsRegistry:
    """In-process counters — scrape via /ai-posture/health/metrics."""

    ai_compliance_gap_total: dict[str, int] = field(default_factory=dict)
    projection_rebuild_total: int = 0
    projection_events_applied_total: int = 0
    risk_scores_computed_total: int = 0

    def inc_gap(self, framework_id: str, amount: int = 1) -> None:
        self.ai_compliance_gap_total[framework_id] = (
            self.ai_compliance_gap_total.get(framework_id, 0) + amount
        )

    def prometheus_text(self) -> str:
        lines = [
            "# HELP ai_compliance_gap_total Compliance gaps by framework",
            "# TYPE ai_compliance_gap_total gauge",
        ]
        for framework, count in sorted(self.ai_compliance_gap_total.items()):
            lines.append(f'ai_compliance_gap_total{{framework="{framework}"}} {count}')
        lines.extend(
            [
                "# HELP m31_projection_rebuild_total Projection rebuild operations",
                "# TYPE m31_projection_rebuild_total counter",
                f"m31_projection_rebuild_total {self.projection_rebuild_total}",
                "# HELP m31_projection_events_applied_total Projection events applied",
                "# TYPE m31_projection_events_applied_total counter",
                f"m31_projection_events_applied_total {self.projection_events_applied_total}",
                "# HELP m31_risk_scores_computed_total Risk scores computed",
                "# TYPE m31_risk_scores_computed_total counter",
                f"m31_risk_scores_computed_total {self.risk_scores_computed_total}",
            ]
        )
        return "\n".join(lines) + "\n"


METRICS = M31MetricsRegistry()

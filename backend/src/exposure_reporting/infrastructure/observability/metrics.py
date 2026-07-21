"""In-process metrics counters for exposure_reporting."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReportingMetrics:
    reports_generated: int = 0
    reports_delivered: int = 0
    mappings_created: int = 0
    mappings_updated: int = 0
    graph_nodes_upserted: int = 0
    graph_edges_upserted: int = 0
    projection_rebuilds: int = 0
    labels: dict[str, str] = field(default_factory=dict)

    def snapshot(self) -> dict[str, object]:
        return {
            "reports_generated": self.reports_generated,
            "reports_delivered": self.reports_delivered,
            "mappings_created": self.mappings_created,
            "mappings_updated": self.mappings_updated,
            "graph_nodes_upserted": self.graph_nodes_upserted,
            "graph_edges_upserted": self.graph_edges_upserted,
            "projection_rebuilds": self.projection_rebuilds,
            "labels": dict(self.labels),
        }

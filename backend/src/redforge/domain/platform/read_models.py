"""Platform read models — Sprint 24.

ReadModels are the output of projections. They are optimised for reads,
not writes. Each projection builds exactly one ReadModel type.

Design rules:
- ReadModels are immutable value objects (frozen dataclasses).
- They contain NO domain logic — projection code produces them.
- They are organisation-scoped — every ReadModel has an organization_id.
- They carry a `last_updated_at` and `last_event_position` for cache
  invalidation and freshness checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

# ── Base read model ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ReadModel:
    """Abstract base for all read models.

    Subclasses must set `model_type` to a stable identifier string so
    repositories can key storage without using type() introspection.
    """

    model_type: str
    organization_id: str
    last_updated_at: datetime
    last_event_position: int


# ── Timeline read models ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Timeline:
    """Ordered sequence of events for a subject (org, asset, campaign, etc.).

    A Timeline is a query result, not a stored entity — it is assembled
    on-demand from the event store and/or read model repository.
    """

    subject_type: str
    subject_id: str
    organization_id: str
    entries: tuple[Any, ...]
    total_events: int
    from_position: int
    to_position: int

    @property
    def is_empty(self) -> bool:
        return not bool(self.entries)


@dataclass(frozen=True, slots=True)
class AuditTimeline:
    """Compliance-grade timeline with actor attribution for every event.

    Extends Timeline with actor context required by security audits.
    """

    subject_type: str
    subject_id: str
    organization_id: str
    entries: tuple[Any, ...]
    total_events: int
    from_position: int
    to_position: int
    actor_summary: dict[str, int]

    @property
    def is_empty(self) -> bool:
        return not bool(self.entries)


# ── Projection-specific read models ───────────────────────────────────────


@dataclass(frozen=True, slots=True)
class InventoryReadModel:
    """Current state of all AI assets for an organisation."""

    organization_id: str
    total_assets: int
    assets_by_type: dict[str, int]
    assets_by_status: dict[str, int]
    recently_discovered: tuple[str, ...]
    last_discovery_at: datetime | None
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "inventory"


@dataclass(frozen=True, slots=True)
class CampaignReadModel:
    """Summary of all campaigns and their current states."""

    organization_id: str
    total_campaigns: int
    campaigns_by_status: dict[str, int]
    active_campaign_ids: tuple[str, ...]
    last_campaign_started_at: datetime | None
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "campaign"


@dataclass(frozen=True, slots=True)
class ValidationReadModel:
    """Aggregate view of validation run outcomes."""

    organization_id: str
    total_validations: int
    validations_by_status: dict[str, int]
    pass_rate: float
    last_validation_at: datetime | None
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "validation"


@dataclass(frozen=True, slots=True)
class EvidenceReadModel:
    """Aggregate view of evidence collected."""

    organization_id: str
    total_evidence: int
    evidence_by_type: dict[str, int]
    evidence_by_severity: dict[str, int]
    last_evidence_at: datetime | None
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "evidence"


@dataclass(frozen=True, slots=True)
class RiskReadModel:
    """Current risk posture for an organisation."""

    organization_id: str
    overall_risk_score: float
    risk_by_category: dict[str, float]
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "risk"


@dataclass(frozen=True, slots=True)
class IntelligenceReadModel:
    """Summary of intelligence insights generated."""

    organization_id: str
    total_insights: int
    insights_by_type: dict[str, int]
    actionable_insights: int
    last_insight_at: datetime | None
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "intelligence"


@dataclass(frozen=True, slots=True)
class ConnectorActivityReadModel:
    """Summary of connector discovery and sync activity."""

    organization_id: str
    total_connectors: int
    active_connectors: int
    total_discoveries: int
    total_syncs: int
    last_discovery_at: datetime | None
    last_sync_at: datetime | None
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "connector_activity"


@dataclass(frozen=True, slots=True)
class OrganizationActivityReadModel:
    """High-level activity summary for an organisation."""

    organization_id: str
    total_events: int
    events_by_bounded_context: dict[str, int]
    last_activity_at: datetime | None
    active_users: int
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "organization_activity"


@dataclass(frozen=True, slots=True)
class AssetTimelineReadModel:
    """Full timeline of events for a specific AI asset."""

    organization_id: str
    asset_id: str
    total_events: int
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    event_type_counts: dict[str, int]
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "asset_timeline"


@dataclass(frozen=True, slots=True)
class KnowledgeGraphReadModel:
    """Snapshot of KG node/edge counts projected from events."""

    organization_id: str
    total_nodes: int
    total_edges: int
    nodes_by_type: dict[str, int]
    last_updated_at: datetime
    last_event_position: int

    @property
    def model_type(self) -> str:
        return "knowledge_graph"

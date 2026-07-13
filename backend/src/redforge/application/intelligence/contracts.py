"""Protocol contracts for the AI Security Intelligence application layer.

All collaborators are @runtime_checkable Protocols. Infrastructure
implements these; the application layer depends only on protocols.

Input DTOs (IntelligenceContext, RiskIncidentInput, SnapshotInput, etc.)
are also defined here — they are the clean interface between the
intelligence engine and the rest of RedForge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.intelligence.entity import (
        Recommendation,
        SecurityInsight,
    )
    from redforge.domain.intelligence.value_objects import (
        AttackCoverageGap,
        PostureNarrative,
        RiskNarrative,
        SecurityGap,
    )


# ─── Input DTOs ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RiskIncidentInput:
    """Lightweight reference to a RiskIncident output from the risk engine.

    Keeps the intelligence engine decoupled from the risk engine's domain types.
    risk_score: 0-10 (the incident's overall score).
    priority: "critical" / "high" / "medium" / "low" / "informational".
    attack_types: set of attack type strings.
    """

    incident_id: str
    organization_id: str
    target_ids: tuple[str, ...]
    risk_score: float
    priority: str
    title: str
    attack_types: frozenset[str] = field(default_factory=frozenset)
    finding_ids: tuple[str, ...] = ()
    evidence_chain_ids: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()


@dataclass(frozen=True)
class FindingInput:
    """Lightweight reference to a Finding for intelligence computation."""

    finding_id: str
    organization_id: str
    target_id: str
    run_id: str
    severity: str
    attack_category: str
    risk_score: float = 0.0
    status: str = "open"
    created_at_iso: str = ""


@dataclass(frozen=True)
class SnapshotInput:
    """Lightweight reference to a ValidationSnapshot."""

    snapshot_id: str
    organization_id: str
    target_id: str
    run_id: str
    vulnerability_rate: float
    total_attacks: int
    finding_count: int
    executed_categories: frozenset[str] = field(default_factory=frozenset)
    model: str = ""
    provider: str = ""
    created_at_iso: str = ""


@dataclass(frozen=True)
class DriftEventInput:
    """Lightweight reference to a DriftEvent."""

    source_snapshot_id: str
    target_snapshot_id: str
    drift_types: tuple[str, ...]
    is_significant: bool
    target_id: str
    organization_id: str


@dataclass(frozen=True)
class PostureInput:
    """Lightweight reference to a SecurityPostureScore."""

    organization_id: str
    mean_vulnerability_rate: float
    level: str
    targets_assessed: int
    total_findings: int
    critical_targets: int
    trend: str
    snapshot_count: int


@dataclass(frozen=True)
class IntelligenceContext:
    """Everything the intelligence engine needs to produce recommendations.

    This is the canonical input boundary — callers build this from
    their available data; the engine depends only on this DTO.

    all_known_attack_categories: the full set of all possible attack category
        values (loaded from the attack library at call site).
    period_days: the time window being analyzed.
    """

    organization_id: str
    target_ids: tuple[str, ...]
    risk_incidents: tuple[RiskIncidentInput, ...] = ()
    findings: tuple[FindingInput, ...] = ()
    snapshots: tuple[SnapshotInput, ...] = ()
    drift_events: tuple[DriftEventInput, ...] = ()
    posture: PostureInput | None = None
    all_known_attack_categories: frozenset[str] = field(default_factory=frozenset)
    period_days: int = 30


# ─── Protocol Ports ──────────────────────────────────────────────────────────


@runtime_checkable
class InsightGeneratorPort(Protocol):
    """Generates SecurityInsights from evidence and risk signals."""

    def generate(self, context: IntelligenceContext) -> list[SecurityInsight]: ...


@runtime_checkable
class CoverageAnalyzerPort(Protocol):
    """Analyzes attack coverage per target."""

    def analyze(self, context: IntelligenceContext) -> list[AttackCoverageGap]: ...


@runtime_checkable
class GapAnalyzerPort(Protocol):
    """Identifies structural security gaps."""

    def analyze(
        self,
        context: IntelligenceContext,
        coverage_gaps: list[AttackCoverageGap],
    ) -> list[SecurityGap]: ...


@runtime_checkable
class RecommendationGeneratorPort(Protocol):
    """Generates Recommendations from context and insights."""

    def generate(
        self,
        context: IntelligenceContext,
        insights: list[SecurityInsight],
        coverage_gaps: list[AttackCoverageGap],
        security_gaps: list[SecurityGap],
    ) -> list[Recommendation]: ...


@runtime_checkable
class PriorityEnginePort(Protocol):
    """Scores, deduplicates, and sorts recommendations."""

    def prioritize(
        self,
        recommendations: list[Recommendation],
        context: IntelligenceContext,
    ) -> list[Recommendation]: ...


@runtime_checkable
class NarrativeBuilderPort(Protocol):
    """Builds human-readable risk and posture narratives."""

    def build_risk_narrative(
        self,
        context: IntelligenceContext,
        recommendations: list[Recommendation],
    ) -> RiskNarrative: ...

    def build_posture_narrative(
        self,
        context: IntelligenceContext,
        coverage_gaps: list[AttackCoverageGap],
    ) -> PostureNarrative: ...


@runtime_checkable
class RecommendationRepositoryPort(Protocol):
    """Persistence port for Recommendation aggregates."""

    async def save(self, recommendation: Recommendation) -> None: ...

    async def get_by_id(self, recommendation_id: str) -> Recommendation | None: ...

    async def list_for_target(
        self,
        organization_id: str,
        target_id: str,
    ) -> list[Recommendation]: ...

    async def list_for_org(
        self,
        organization_id: str,
        status: str | None = None,
    ) -> list[Recommendation]: ...

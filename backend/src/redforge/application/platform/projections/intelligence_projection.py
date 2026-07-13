"""IntelligenceProjection — tracks security intelligence insights."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import IntelligenceReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class IntelligenceProjection(ProjectionBase):
    """Tracks intelligence insight counts and actionability."""

    projection_name = "intelligence"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._total: dict[str, int] = {}
        self._by_type: dict[str, dict[str, int]] = {}
        self._actionable: dict[str, int] = {}
        self._last_at: dict[str, datetime | None] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        engine.register(self.projection_name, "intelligence.InsightGenerated", self._handle)
        engine.register(self.projection_name, "intelligence.RecommendationCreated", self._handle)
        engine.register(self.projection_name, "intelligence.ThreatDetected", self._handle)
        engine.register(self.projection_name, "intelligence.RiskInsightGenerated", self._handle)

    def _init_org(self, org: str) -> None:
        if org not in self._total:
            self._total[org] = 0
            self._by_type[org] = {}
            self._actionable[org] = 0
            self._last_at[org] = None

    async def _handle(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._total[org] += 1
        insight_type = envelope.metadata.get_custom("insight_type") or envelope.event_type
        self._by_type[org][insight_type] = self._by_type[org].get(insight_type, 0) + 1
        if envelope.metadata.get_custom("actionable") == "true":
            self._actionable[org] += 1
        self._last_at[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _persist(self, org: str) -> None:
        model = IntelligenceReadModel(
            organization_id=org,
            total_insights=self._total.get(org, 0),
            insights_by_type=dict(self._by_type.get(org, {})),
            actionable_insights=self._actionable.get(org, 0),
            last_insight_at=self._last_at.get(org),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> IntelligenceReadModel | None:
        loaded = await self._repo.load("intelligence", organization_id)
        return cast("IntelligenceReadModel | None", loaded)

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)

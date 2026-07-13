"""RiskProjection — aggregates risk scores and finding severity counts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import RiskReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RiskProjection(ProjectionBase):
    """Aggregates risk scores from finding and posture events."""

    projection_name = "risk"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._scores: dict[str, list[float]] = {}
        self._by_category: dict[str, dict[str, list[float]]] = {}
        self._critical: dict[str, int] = {}
        self._high: dict[str, int] = {}
        self._medium: dict[str, int] = {}
        self._low: dict[str, int] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        engine.register(self.projection_name, "findings.FindingCreated", self._handle_finding)
        engine.register(self.projection_name, "posture.RiskScoreUpdated", self._handle_risk_score)
        engine.register(self.projection_name, "posture.PostureAssessed", self._handle_posture)
        engine.register(
            self.projection_name, "intelligence.RiskInsightGenerated", self._handle_insight
        )

    def _init_org(self, org: str) -> None:
        if org not in self._scores:
            self._scores[org] = []
            self._by_category[org] = {}
            self._critical[org] = 0
            self._high[org] = 0
            self._medium[org] = 0
            self._low[org] = 0

    async def _handle_finding(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        severity = envelope.metadata.get_custom("severity") or "low"
        severity_map: dict[str, str] = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        severity = severity_map.get(severity.lower(), "low")
        counter_map: dict[str, dict[str, int]] = {
            "critical": self._critical,
            "high": self._high,
            "medium": self._medium,
            "low": self._low,
        }
        counter_map[severity][org] = counter_map[severity].get(org, 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_risk_score(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        score_str = envelope.metadata.get_custom("risk_score") or "0.0"
        try:
            score = float(score_str)
        except ValueError:
            score = 0.0
        self._scores[org].append(score)
        category = envelope.metadata.get_custom("category") or "overall"
        self._by_category[org].setdefault(category, []).append(score)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_posture(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_insight(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    def _avg(self, scores: list[float]) -> float:
        return sum(scores) / len(scores) if scores else 0.0

    async def _persist(self, org: str) -> None:
        risk_by_category = {
            cat: self._avg(scores)
            for cat, scores in self._by_category.get(org, {}).items()
        }
        model = RiskReadModel(
            organization_id=org,
            overall_risk_score=self._avg(self._scores.get(org, [])),
            risk_by_category=risk_by_category,
            critical_findings=self._critical.get(org, 0),
            high_findings=self._high.get(org, 0),
            medium_findings=self._medium.get(org, 0),
            low_findings=self._low.get(org, 0),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> RiskReadModel | None:
        return cast("RiskReadModel | None", await self._repo.load("risk", organization_id))

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)

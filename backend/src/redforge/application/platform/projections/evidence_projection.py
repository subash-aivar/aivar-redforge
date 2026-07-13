"""EvidenceProjection — tracks evidence collected per organisation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import EvidenceReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class EvidenceProjection(ProjectionBase):
    """Tracks total evidence items and breakdowns by type and severity."""

    projection_name = "evidence"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._total: dict[str, int] = {}
        self._by_type: dict[str, dict[str, int]] = {}
        self._by_severity: dict[str, dict[str, int]] = {}
        self._last_at: dict[str, datetime | None] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        engine.register(self.projection_name, "evidence.EvidenceCreated", self._handle)
        engine.register(self.projection_name, "evidence.EvidenceRecorded", self._handle)
        engine.register(self.projection_name, "evidence.EvidenceCollected", self._handle)

    def _init_org(self, org: str) -> None:
        if org not in self._total:
            self._total[org] = 0
            self._by_type[org] = {}
            self._by_severity[org] = {}
            self._last_at[org] = None

    async def _handle(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._total[org] += 1
        ev_type = envelope.metadata.get_custom("evidence_type") or "unknown"
        severity = envelope.metadata.get_custom("severity") or "info"
        self._by_type[org][ev_type] = self._by_type[org].get(ev_type, 0) + 1
        self._by_severity[org][severity] = self._by_severity[org].get(severity, 0) + 1
        self._last_at[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _persist(self, org: str) -> None:
        model = EvidenceReadModel(
            organization_id=org,
            total_evidence=self._total.get(org, 0),
            evidence_by_type=dict(self._by_type.get(org, {})),
            evidence_by_severity=dict(self._by_severity.get(org, {})),
            last_evidence_at=self._last_at.get(org),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> EvidenceReadModel | None:
        return cast("EvidenceReadModel | None", await self._repo.load("evidence", organization_id))

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)

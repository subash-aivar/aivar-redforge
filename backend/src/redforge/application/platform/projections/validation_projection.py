"""ValidationProjection — tracks validation run outcomes and pass rates."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from redforge.application.platform.projection_engine import ProjectionEngine
from redforge.application.platform.projections.base import ProjectionBase
from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.read_models import ValidationReadModel


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ValidationProjection(ProjectionBase):
    """Tracks validation results and computes pass rate."""

    projection_name = "validation"

    def __init__(self, repo: Any) -> None:
        self._repo = repo
        self._by_status: dict[str, dict[str, int]] = {}
        self._total: dict[str, int] = {}
        self._passed: dict[str, int] = {}
        self._last_at: dict[str, datetime | None] = {}
        self._last_positions: dict[str, int] = {}

    def register_with(self, engine: ProjectionEngine) -> None:
        pn = self.projection_name
        engine.register(pn, "validation.ValidationRunStarted", self._handle_started)
        engine.register(pn, "validation.ValidationRunCompleted", self._handle_completed)
        engine.register(pn, "validation.ValidationRunFailed", self._handle_failed)
        engine.register(pn, "validation.ValidationPassed", self._handle_passed)
        engine.register(pn, "validation.ValidationFailed", self._handle_status_failed)

    def _init_org(self, org: str) -> None:
        if org not in self._by_status:
            self._by_status[org] = {}
            self._total[org] = 0
            self._passed[org] = 0
            self._last_at[org] = None

    async def _handle_started(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._total[org] += 1
        self._by_status[org]["running"] = self._by_status[org].get("running", 0) + 1
        self._last_at[org] = envelope.occurred_at
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_completed(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        running = self._by_status[org].get("running", 0)
        if running > 0:
            self._by_status[org]["running"] = running - 1
        self._by_status[org]["completed"] = self._by_status[org].get("completed", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_failed(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._by_status[org]["failed"] = self._by_status[org].get("failed", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_passed(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._passed[org] = self._passed.get(org, 0) + 1
        self._by_status[org]["passed"] = self._by_status[org].get("passed", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _handle_status_failed(self, envelope: EventEnvelope) -> None:
        org = envelope.organization_id
        self._init_org(org)
        self._by_status[org]["failed_check"] = self._by_status[org].get("failed_check", 0) + 1
        self._last_positions[org] = envelope.global_position
        await self._persist(org)

    async def _persist(self, org: str) -> None:
        total = self._total.get(org, 0)
        passed = self._passed.get(org, 0)
        pass_rate = (passed / total) if total > 0 else 0.0
        model = ValidationReadModel(
            organization_id=org,
            total_validations=total,
            validations_by_status=dict(self._by_status.get(org, {})),
            pass_rate=pass_rate,
            last_validation_at=self._last_at.get(org),
            last_updated_at=_utc_now(),
            last_event_position=self._last_positions.get(org, 0),
        )
        await self._repo.save(model)

    async def get(self, organization_id: str) -> ValidationReadModel | None:
        loaded = await self._repo.load("validation", organization_id)
        return cast("ValidationReadModel | None", loaded)

    async def flush_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        model = await self._repo.load(self.projection_name, organization_id)
        if model is not None:
            await target_repo.save(model)

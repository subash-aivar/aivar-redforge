"""Repositories for M22 Phase 6 sync state and path-compute debounce."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.database.models.threat_intel_sync import (
    InvestigationPathComputeStateModel,
    ThreatIntelSyncStateModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_MIN_PATH_RECOMPUTE_SECONDS = 300  # hardening: ≥5 minutes debounce
_MIN_EVIDENCE_DELTA = 1


class SqlAlchemyThreatIntelSyncStateRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, job_key: str) -> ThreatIntelSyncStateModel | None:
        return await self._session.get(ThreatIntelSyncStateModel, job_key)

    async def list_all(self) -> list[ThreatIntelSyncStateModel]:
        result = await self._session.execute(select(ThreatIntelSyncStateModel))
        return list(result.scalars().all())

    async def mark_started(self, job_key: str, *, now: datetime | None = None) -> None:
        clock = now or datetime.now(UTC)
        model = await self.get(job_key)
        if model is None:
            model = ThreatIntelSyncStateModel(
                job_key=job_key,
                last_started_at=clock,
                last_finished_at=None,
                last_status="running",
                last_error=None,
                last_result={},
                updated_at=clock,
            )
            self._session.add(model)
        else:
            model.last_started_at = clock
            model.last_status = "running"
            model.last_error = None
            model.updated_at = clock
        await self._session.flush()

    async def mark_finished(
        self,
        job_key: str,
        *,
        status: str,
        result: dict[str, Any],
        error: str | None = None,
        now: datetime | None = None,
    ) -> None:
        clock = now or datetime.now(UTC)
        model = await self.get(job_key)
        if model is None:
            model = ThreatIntelSyncStateModel(
                job_key=job_key,
                last_started_at=clock,
                last_finished_at=clock,
                last_status=status,
                last_error=error,
                last_result=result,
                updated_at=clock,
            )
            self._session.add(model)
        else:
            model.last_finished_at = clock
            model.last_status = status
            model.last_error = error
            model.last_result = result
            model.updated_at = clock
        await self._session.flush()


class SqlAlchemyInvestigationPathComputeStateRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(
        self, organization_id: str, investigation_id: str
    ) -> InvestigationPathComputeStateModel | None:
        return await self._session.get(
            InvestigationPathComputeStateModel,
            (organization_id, investigation_id),
        )

    async def record_evidence(
        self, organization_id: str, investigation_id: str, *, now: datetime | None = None
    ) -> InvestigationPathComputeStateModel:
        clock = now or datetime.now(UTC)
        model = await self.get(organization_id, investigation_id)
        if model is None:
            model = InvestigationPathComputeStateModel(
                organization_id=organization_id,
                investigation_id=investigation_id,
                last_compute_at=None,
                pending_evidence_count=1,
                updated_at=clock,
            )
            self._session.add(model)
        else:
            model.pending_evidence_count += 1
            model.updated_at = clock
        await self._session.flush()
        return model

    def may_compute(
        self,
        model: InvestigationPathComputeStateModel | None,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Debounce: recompute only after ≥5 min or ≥1 new evidence since last."""
        clock = now or datetime.now(UTC)
        if model is None:
            return True
        if model.last_compute_at is None:
            return model.pending_evidence_count >= _MIN_EVIDENCE_DELTA
        elapsed = (clock - model.last_compute_at).total_seconds()
        if elapsed >= _MIN_PATH_RECOMPUTE_SECONDS:
            return True
        return model.pending_evidence_count >= 3

    async def mark_computed(
        self, organization_id: str, investigation_id: str, *, now: datetime | None = None
    ) -> None:
        clock = now or datetime.now(UTC)
        model = await self.get(organization_id, investigation_id)
        if model is None:
            model = InvestigationPathComputeStateModel(
                organization_id=organization_id,
                investigation_id=investigation_id,
                last_compute_at=clock,
                pending_evidence_count=0,
                updated_at=clock,
            )
            self._session.add(model)
        else:
            model.last_compute_at = clock
            model.pending_evidence_count = 0
            model.updated_at = clock
        await self._session.flush()

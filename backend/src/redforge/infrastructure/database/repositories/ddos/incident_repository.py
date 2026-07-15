"""DDoS incident and mitigation repositories — M19.

Incident updates use optimistic concurrency (version column) to prevent
concurrent worker writes from overwriting each other's state transitions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.ddos import (
    DDoSIncidentEventModel,
    DDoSIncidentModel,
    DDoSMitigationRecommendationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyDDoSIncidentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self, organization_id: str, incident_id: str
    ) -> DDoSIncidentModel | None:
        stmt = select(DDoSIncidentModel).where(
            DDoSIncidentModel.organization_id == organization_id,
            DDoSIncidentModel.id == incident_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_open_for_resource(
        self, organization_id: str, resource_id: str
    ) -> DDoSIncidentModel | None:
        """Return the most recent open incident for a resource, if any."""
        stmt = (
            select(DDoSIncidentModel)
            .where(
                DDoSIncidentModel.organization_id == organization_id,
                DDoSIncidentModel.resource_id == resource_id,
                DDoSIncidentModel.status.in_([
                    "DETECTED", "ACTIVE", "ESCALATED", "MITIGATING", "MONITORING"
                ]),
            )
            .order_by(DDoSIncidentModel.first_detected_at.desc())
            .limit(1)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for_org(
        self,
        organization_id: str,
        status_filter: list[str] | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DDoSIncidentModel]:
        stmt = (
            select(DDoSIncidentModel)
            .where(DDoSIncidentModel.organization_id == organization_id)
            .order_by(DDoSIncidentModel.first_detected_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if status_filter:
            stmt = stmt.where(DDoSIncidentModel.status.in_(status_filter))
        if resource_id:
            stmt = stmt.where(DDoSIncidentModel.resource_id == resource_id)
        return list((await self._session.execute(stmt)).scalars().all())

    async def list_active_for_org(
        self, organization_id: str
    ) -> list[DDoSIncidentModel]:
        return await self.list_for_org(
            organization_id,
            status_filter=["DETECTED", "ACTIVE", "ESCALATED", "MITIGATING", "MONITORING"],
        )

    async def create(self, model: DDoSIncidentModel) -> DDoSIncidentModel:
        """Create a new incident; idempotent via concurrent duplicate prevention.

        Uses SAVEPOINT + refetch pattern (established M16/M17/M18 pattern)
        for concurrent first-detection scenarios — ensures exactly one
        incident opens even when multiple detection workers fire simultaneously.
        """
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model
        except IntegrityError:
            existing = await self.get_open_for_resource(model.organization_id, model.resource_id)
            if existing is None:
                raise
            return existing

    async def update_status(
        self,
        organization_id: str,
        incident_id: str,
        new_status: str,
        current_version: int,
        updates: dict[str, Any] | None = None,
    ) -> bool:
        """Optimistic-concurrency update. Returns True iff exactly one row
        was updated (i.e., version matched and no concurrent transition won).

        This prevents two concurrent workers both transitioning the same
        incident: the second update finds version != current_version and
        returns False without touching the row.
        """
        set_values: dict[str, Any] = {
            "status": new_status,
            "last_updated_at": datetime.now(UTC),
            "version": current_version + 1,
        }
        if updates:
            set_values.update(updates)

        stmt = (
            update(DDoSIncidentModel)
            .where(
                DDoSIncidentModel.organization_id == organization_id,
                DDoSIncidentModel.id == incident_id,
                DDoSIncidentModel.version == current_version,
            )
            .values(**set_values)
        )
        result = await self._session.execute(stmt)
        return result.rowcount == 1  # type: ignore[attr-defined,no-any-return]

    async def update_metrics(
        self,
        organization_id: str,
        incident_id: str,
        updates: dict[str, Any],
    ) -> None:
        """Non-versioned update for metric fields (peak_*, latest_evidence).

        These are best-effort metric updates, not state transitions, so
        they do not use optimistic concurrency — a race on metric updates
        is acceptable (last writer wins on continuous numeric fields).
        """
        updates["last_updated_at"] = datetime.now(UTC)
        stmt = (
            update(DDoSIncidentModel)
            .where(
                DDoSIncidentModel.organization_id == organization_id,
                DDoSIncidentModel.id == incident_id,
            )
            .values(**updates)
        )
        await self._session.execute(stmt)

    async def increment_quiet_windows(
        self,
        organization_id: str,
        incident_id: str,
    ) -> int:
        """Increment consecutive_quiet_windows and return new value."""
        incident = await self.get_by_id(organization_id, incident_id)
        if incident is None:
            return 0
        new_count = incident.consecutive_quiet_windows + 1
        incident.consecutive_quiet_windows = new_count
        incident.last_updated_at = datetime.now(UTC)
        await self._session.flush()
        return new_count

    async def reset_quiet_windows(
        self,
        organization_id: str,
        incident_id: str,
    ) -> None:
        incident = await self.get_by_id(organization_id, incident_id)
        if incident is not None:
            incident.consecutive_quiet_windows = 0
            incident.last_updated_at = datetime.now(UTC)
            await self._session.flush()


class SqlAlchemyDDoSIncidentEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, model: DDoSIncidentEventModel) -> DDoSIncidentEventModel:
        self._session.add(model)
        await self._session.flush()
        return model

    async def list_for_incident(
        self,
        organization_id: str,
        incident_id: str,
        limit: int = 200,
    ) -> list[DDoSIncidentEventModel]:
        stmt = (
            select(DDoSIncidentEventModel)
            .where(
                DDoSIncidentEventModel.organization_id == organization_id,
                DDoSIncidentEventModel.incident_id == incident_id,
            )
            .order_by(DDoSIncidentEventModel.occurred_at.asc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def list_for_org_since(
        self,
        organization_id: str,
        since: datetime,
        limit: int = 200,
    ) -> list[DDoSIncidentEventModel]:
        stmt = (
            select(DDoSIncidentEventModel)
            .where(
                DDoSIncidentEventModel.organization_id == organization_id,
                DDoSIncidentEventModel.occurred_at >= since,
            )
            .order_by(DDoSIncidentEventModel.occurred_at.asc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())


class SqlAlchemyMitigationRecommendationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self, organization_id: str, rec_id: str
    ) -> DDoSMitigationRecommendationModel | None:
        stmt = select(DDoSMitigationRecommendationModel).where(
            DDoSMitigationRecommendationModel.organization_id == organization_id,
            DDoSMitigationRecommendationModel.id == rec_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def create(
        self, model: DDoSMitigationRecommendationModel
    ) -> DDoSMitigationRecommendationModel:
        self._session.add(model)
        await self._session.flush()
        return model

    async def list_for_incident(
        self,
        organization_id: str,
        incident_id: str,
    ) -> list[DDoSMitigationRecommendationModel]:
        stmt = (
            select(DDoSMitigationRecommendationModel)
            .where(
                DDoSMitigationRecommendationModel.organization_id == organization_id,
                DDoSMitigationRecommendationModel.incident_id == incident_id,
            )
            .order_by(DDoSMitigationRecommendationModel.created_at.asc())
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def list_pending_for_org(
        self, organization_id: str, limit: int = 50
    ) -> list[DDoSMitigationRecommendationModel]:
        stmt = (
            select(DDoSMitigationRecommendationModel)
            .where(
                DDoSMitigationRecommendationModel.organization_id == organization_id,
                DDoSMitigationRecommendationModel.approval_status == "PENDING",
            )
            .order_by(DDoSMitigationRecommendationModel.created_at.desc())
            .limit(limit)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def approve(
        self,
        organization_id: str,
        rec_id: str,
        approved_by: str,
    ) -> DDoSMitigationRecommendationModel | None:
        """Atomic first-writer-wins approval.

        Uses UPDATE WHERE approval_status = 'PENDING' so that concurrent
        callers cannot both transition the same recommendation. Exactly one
        caller will see rowcount == 1; all others see 0 and get the already-
        transitioned row back. No TOCTOU race, no duplicate audit side effects.
        Returns None if the recommendation does not exist.
        """
        now = datetime.now(UTC)
        stmt = (
            update(DDoSMitigationRecommendationModel)
            .where(
                DDoSMitigationRecommendationModel.organization_id == organization_id,
                DDoSMitigationRecommendationModel.id == rec_id,
                DDoSMitigationRecommendationModel.approval_status == "PENDING",
            )
            .values(
                approval_status="APPROVED",
                approved_by=approved_by,
                approved_at=now,
                updated_at=now,
            )
        )
        await self._session.execute(stmt)
        return await self.get_by_id(organization_id, rec_id)

    async def reject(
        self,
        organization_id: str,
        rec_id: str,
        rejected_by: str,
        reason: str,
    ) -> DDoSMitigationRecommendationModel | None:
        """Atomic first-writer-wins rejection — same CAS pattern as approve()."""
        now = datetime.now(UTC)
        stmt = (
            update(DDoSMitigationRecommendationModel)
            .where(
                DDoSMitigationRecommendationModel.organization_id == organization_id,
                DDoSMitigationRecommendationModel.id == rec_id,
                DDoSMitigationRecommendationModel.approval_status == "PENDING",
            )
            .values(
                approval_status="REJECTED",
                rejected_by=rejected_by,
                rejected_at=now,
                rejection_reason=reason,
                updated_at=now,
            )
        )
        await self._session.execute(stmt)
        return await self.get_by_id(organization_id, rec_id)

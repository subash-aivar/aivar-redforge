"""SqlAlchemy repository for the NetworkValidationRun aggregate (M16)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from redforge.domain.network_security.entity import NetworkValidationRun
from redforge.domain.network_security.value_objects import (
    NetworkRunStatus,
    NetworkValidationProfile,
)
from redforge.infrastructure.database.models.network_security import NetworkValidationRunModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _to_entity(model: NetworkValidationRunModel) -> NetworkValidationRun:
    return NetworkValidationRun(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        target_asset_id=EntityId.from_string(model.target_asset_id),
        requester_user_id=EntityId.from_string(model.requester_user_id),
        profile=NetworkValidationProfile(model.profile),
        status=NetworkRunStatus(model.status),
        timestamps=AuditTimestamps(created_at=model.created_at, updated_at=model.updated_at),
        trigger=model.trigger,
        continuous_policy_id=(
            EntityId.from_string(model.continuous_policy_id)
            if model.continuous_policy_id else None
        ),
        scheduled_due_at=model.scheduled_due_at,
        authorization_id=(
            EntityId.from_string(model.authorization_id) if model.authorization_id else None
        ),
        started_at=model.started_at,
        finished_at=model.finished_at,
        cancellation_requested=model.cancellation_requested,
    )


def _to_model(run: NetworkValidationRun) -> NetworkValidationRunModel:
    return NetworkValidationRunModel(
        id=str(run.id),
        organization_id=str(run.organization_id),
        target_asset_id=str(run.target_asset_id),
        requester_user_id=str(run.requester_user_id),
        profile=str(run.profile),
        status=str(run.status),
        trigger=run.trigger,
        continuous_policy_id=str(run.continuous_policy_id) if run.continuous_policy_id else None,
        scheduled_due_at=run.scheduled_due_at,
        authorization_id=str(run.authorization_id) if run.authorization_id else None,
        failure_reason="",
        cancellation_requested=run.cancellation_requested,
        created_at=run.timestamps.created_at,
        updated_at=run.timestamps.updated_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


_TERMINAL_STATUSES = (
    str(NetworkRunStatus.COMPLETED),
    str(NetworkRunStatus.PARTIALLY_COMPLETED),
    str(NetworkRunStatus.FAILED),
    str(NetworkRunStatus.CANCELLED),
)


class SqlAlchemyNetworkValidationRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id_for_organization(
        self, run_id: EntityId, organization_id: EntityId,
    ) -> NetworkValidationRun | None:
        model = await self._get_model(str(run_id), str(organization_id))
        return _to_entity(model) if model is not None else None

    async def list_for_organization(
        self, organization_id: EntityId, limit: int, offset: int,
    ) -> list[NetworkValidationRun]:
        stmt = (
            select(NetworkValidationRunModel)
            .where(NetworkValidationRunModel.organization_id == str(organization_id))
            .order_by(NetworkValidationRunModel.created_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_entity(m) for m in result.scalars().all()]

    async def save(self, run: NetworkValidationRun) -> None:
        existing = await self._get_model(str(run.id), str(run.organization_id))
        model = _to_model(run)
        if existing is None:
            self._session.add(model)
        else:
            existing.status = model.status
            existing.authorization_id = model.authorization_id
            existing.failure_reason = model.failure_reason
            existing.updated_at = model.updated_at
            existing.started_at = model.started_at
            existing.finished_at = model.finished_at
        await self._session.flush()

    async def request_cancellation(
        self, run_id: EntityId, organization_id: EntityId,
    ) -> str | None:
        """Atomically flip cancellation_requested to true, scoped to this
        tenant, only while the run is not already terminal. Deliberately
        NOT routed through save()/_to_model() — a stale in-memory
        aggregate loaded before this call and saved after it can never
        clobber this flag, because save()'s UPDATE branch never writes
        this column at all. Returns the run's current status (fetched in
        the same statement) if the run exists, or None if no such run
        exists for this tenant."""
        stmt = (
            update(NetworkValidationRunModel)
            .where(
                NetworkValidationRunModel.id == str(run_id),
                NetworkValidationRunModel.organization_id == str(organization_id),
                NetworkValidationRunModel.status.notin_(_TERMINAL_STATUSES),
            )
            .values(cancellation_requested=True)
            .returning(NetworkValidationRunModel.status)
        )
        result = await self._session.execute(stmt)
        row = result.first()
        if row is not None:
            await self._session.flush()
            return str(row[0])
        existing = await self._get_model(str(run_id), str(organization_id))
        return str(existing.status) if existing is not None else None

    async def is_cancellation_requested(
        self, run_id: EntityId, organization_id: EntityId,
    ) -> bool:
        stmt = select(NetworkValidationRunModel.cancellation_requested).where(
            NetworkValidationRunModel.id == str(run_id),
            NetworkValidationRunModel.organization_id == str(organization_id),
        )
        result = await self._session.execute(stmt)
        value = result.scalar_one_or_none()
        return bool(value)

    async def _get_model(
        self, run_id: str, organization_id: str,
    ) -> NetworkValidationRunModel | None:
        stmt = select(NetworkValidationRunModel).where(
            NetworkValidationRunModel.id == run_id,
            NetworkValidationRunModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

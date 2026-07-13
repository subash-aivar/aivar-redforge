"""NetworkValidationRunQueryService — M16.

Tenant-scoped read model for NetworkValidationRun — closes a genuine
gap found during adversarial traceability review: no API surface
existed to list or inspect a run's own detail, so cross-tenant
non-disclosure for a run could not be proven at the HTTP layer. Never
computes truth — purely reads back the persisted NetworkValidationRun
aggregate via the existing repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError
from redforge.infrastructure.database.repositories.network_security.run_repository import (
    SqlAlchemyNetworkValidationRunRepository,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.domain.network_security.entity import NetworkValidationRun


@dataclass(frozen=True, slots=True)
class NetworkValidationRunDetailDTO:
    id: str
    organization_id: str
    target_asset_id: str
    requester_user_id: str
    profile: str
    status: str
    trigger: str
    continuous_policy_id: str | None
    authorization_id: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    cancellation_requested: bool


def _to_dto(run: NetworkValidationRun) -> NetworkValidationRunDetailDTO:
    return NetworkValidationRunDetailDTO(
        id=str(run.id), organization_id=str(run.organization_id),
        target_asset_id=str(run.target_asset_id), requester_user_id=str(run.requester_user_id),
        profile=str(run.profile), status=str(run.status), trigger=run.trigger,
        continuous_policy_id=(
            str(run.continuous_policy_id) if run.continuous_policy_id else None
        ),
        authorization_id=str(run.authorization_id) if run.authorization_id else None,
        created_at=run.timestamps.created_at.isoformat(),
        started_at=run.started_at.isoformat() if run.started_at else None,
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        cancellation_requested=run.cancellation_requested,
    )


class NetworkValidationRunQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_for_org(
        self, run_id: str, organization_id: str,
    ) -> NetworkValidationRunDetailDTO:
        try:
            safe_run_id = EntityId.from_string(run_id)
            safe_org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise NotFoundError("NetworkValidationRun", run_id) from exc

        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            run = await repo.get_by_id_for_organization(safe_run_id, safe_org_id)
        if run is None:
            raise NotFoundError("NetworkValidationRun", run_id)
        return _to_dto(run)

    async def list_for_org(
        self, organization_id: str, limit: int = 100, offset: int = 0,
    ) -> list[NetworkValidationRunDetailDTO]:
        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            runs = await repo.list_for_organization(
                EntityId.from_string(organization_id), limit, offset,
            )
        return [_to_dto(r) for r in runs]

    async def request_cancellation(
        self, run_id: str, organization_id: str,
    ) -> NetworkValidationRunDetailDTO:
        """Idempotent: cancelling an already-cancelled or otherwise
        terminal run is not an error — it simply returns the run's
        current (already-terminal) detail unchanged. Malformed IDs and
        unknown/cross-tenant runs both raise the same NotFoundError,
        matching get_for_org's non-disclosure behavior."""
        try:
            safe_run_id = EntityId.from_string(run_id)
            safe_org_id = EntityId.from_string(organization_id)
        except ValueError as exc:
            raise NotFoundError("NetworkValidationRun", run_id) from exc

        async with self._session_factory() as session:
            repo = SqlAlchemyNetworkValidationRunRepository(session)
            status = await repo.request_cancellation(safe_run_id, safe_org_id)
            if status is None:
                raise NotFoundError("NetworkValidationRun", run_id)
            await session.commit()
            run = await repo.get_by_id_for_organization(safe_run_id, safe_org_id)

        assert run is not None  # request_cancellation returned non-None status above
        return _to_dto(run)

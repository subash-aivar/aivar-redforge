"""Persist and query append-only cloud risk history."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.value_objects import OrganizationId

if TYPE_CHECKING:
    from redforge.domain.cloud_security.risk.repositories import CloudRiskHistoryRepository

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
RepoFactory = Callable[[AsyncSession], Any]


class RiskHistoryService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        history_repo_factory: RepoFactory,
    ) -> None:
        self._session_factory = session_factory
        self._history_repo_factory = history_repo_factory

    async def record(self, score: CloudRiskScore) -> None:
        async with self._session_factory() as session:
            repo: CloudRiskHistoryRepository = self._history_repo_factory(session)
            await repo.append_from_score(score)
            await session.commit()

    async def list_for_asset(
        self,
        organization_id: str,
        asset_id: UUID,
        *,
        limit: int = 50,
    ) -> list[dict[str, object]]:
        async with self._session_factory() as session:
            repo: CloudRiskHistoryRepository = self._history_repo_factory(session)
            return await repo.list_for_asset(
                asset_id,
                organization_id=OrganizationId(organization_id),
                limit=limit,
            )

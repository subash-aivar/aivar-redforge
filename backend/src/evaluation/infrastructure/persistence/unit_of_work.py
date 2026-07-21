"""PostgreSQL Unit of Work for evaluation context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evaluation.application.ports.i_unit_of_work import IUnitOfWork
from evaluation.infrastructure.persistence.repositories.pg_campaign_evaluation_repository import (
    PgCampaignEvaluationRepository,
)
from evaluation.infrastructure.persistence.repositories.pg_metrics_snapshot_repository import (
    PgMetricsSnapshotRepository,
)

if TYPE_CHECKING:
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession


class PgUnitOfWork(IUnitOfWork):
    def __init__(self, session: AsyncSession) -> None:
        super().__init__()
        self._session = session
        self.evaluations = PgCampaignEvaluationRepository(session)
        self.metrics_snapshots = PgMetricsSnapshotRepository(session)

    async def commit(self) -> None:
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        await self._session.rollback()

    async def __aenter__(self) -> PgUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None or not self._committed:
            await self.rollback()

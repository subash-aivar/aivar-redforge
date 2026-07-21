"""IUnitOfWork — abstract unit-of-work for evaluation context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from evaluation.domain.repositories.i_campaign_evaluation_repository import (
        ICampaignEvaluationRepository,
    )
    from evaluation.domain.repositories.i_campaign_metrics_snapshot_repository import (
        ICampaignMetricsSnapshotRepository,
    )


class IUnitOfWork(ABC):
    evaluations: ICampaignEvaluationRepository
    metrics_snapshots: ICampaignMetricsSnapshotRepository

    def __init__(self) -> None:
        self._committed = False

    @abstractmethod
    async def commit(self) -> None:
        self._committed = True

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...

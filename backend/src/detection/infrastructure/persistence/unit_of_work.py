"""DetectionUnitOfWork — transactional boundary for detection repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.application.ports.i_unit_of_work import IUnitOfWork
from detection.infrastructure.persistence.repositories.pg_detection_evidence_repository import (
    PgDetectionEvidenceRepository,
)
from detection.infrastructure.persistence.repositories.pg_detection_exception_repository import (
    PgDetectionExceptionRepository,
)
from detection.infrastructure.persistence.repositories.pg_detection_execution_repository import (
    PgDetectionExecutionRepository,
)
from detection.infrastructure.persistence.repositories.pg_detection_finding_repository import (
    PgDetectionFindingRepository,
)
from detection.infrastructure.persistence.repositories.pg_detection_pack_repository import (
    PgDetectionPackRepository,
)
from detection.infrastructure.persistence.repositories.pg_detection_rule_repository import (
    PgDetectionRuleRepository,
)
from detection.infrastructure.persistence.repositories.pg_telemetry_source_repository import (
    PgTelemetrySourceRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class DetectionUnitOfWork(IUnitOfWork):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> DetectionUnitOfWork:
        self._session = self._session_factory()
        assert self._session is not None
        self.detection_rules = PgDetectionRuleRepository(self._session)
        self.telemetry_sources = PgTelemetrySourceRepository(self._session)
        self.detection_executions = PgDetectionExecutionRepository(self._session)
        self.detection_findings = PgDetectionFindingRepository(self._session)
        self.detection_packs = PgDetectionPackRepository(self._session)
        self.detection_exceptions = PgDetectionExceptionRepository(self._session)
        self.detection_evidence = PgDetectionEvidenceRepository(self._session)
        return self

    async def commit(self) -> None:
        if self._session is None:
            return
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        if self._session is not None:
            await self._session.rollback()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed and self._session is not None:
            await self._session.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None


def make_detection_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[], DetectionUnitOfWork]:
    def factory() -> DetectionUnitOfWork:
        return DetectionUnitOfWork(session_factory)

    return factory

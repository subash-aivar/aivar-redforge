from __future__ import annotations

from typing import TYPE_CHECKING, Any

from lessons_learned.application.services.lessons_application_service import (
    LessonsApplicationService,
)
from lessons_learned.infrastructure.acl.ports import (
    InMemoryCampaignRetargetingEventBus,
    InMemoryPostIncidentReportDeliveryPort,
    InMemoryReportArtifactStore,
)
from lessons_learned.infrastructure.persistence.in_memory_repositories import (
    InMemoryLessonsLearnedRepository,
    InMemoryPostIncidentReportRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class LessonsLearnedContainer:
    # No domain ABC exists for these repos in this bounded context (see
    # postgres_repositories.py docstring) — LessonsApplicationService
    # itself already types its repo params as Any, so these follow suit
    # rather than inventing a Protocol this context has never had.
    ll_repo: Any
    report_repo: Any

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        if session_factory is not None:
            from lessons_learned.infrastructure.persistence.postgres_repositories import (
                PgLessonsLearnedRepository,
                PgPostIncidentReportRepository,
            )

            self.ll_repo = PgLessonsLearnedRepository(session_factory)
            self.report_repo = PgPostIncidentReportRepository(session_factory)
        else:
            self.ll_repo = InMemoryLessonsLearnedRepository()
            self.report_repo = InMemoryPostIncidentReportRepository()
        self.bus = InMemoryCampaignRetargetingEventBus()
        self.store = InMemoryReportArtifactStore()
        self.delivery = InMemoryPostIncidentReportDeliveryPort()
        self.app = LessonsApplicationService(
            self.ll_repo, self.report_repo, self.bus, self.store, self.delivery
        )

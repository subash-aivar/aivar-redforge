from __future__ import annotations

from typing import TYPE_CHECKING

from playbook.application.services.playbook_application_service import PlaybookApplicationService
from playbook.infrastructure.observability.metrics_store import OperationalMetricsStore
from playbook.infrastructure.persistence.in_memory_repositories import (
    InMemoryAutomationPolicyRepository,
    InMemoryPlaybookRepository,
    InMemoryPlaybookTestResultRepository,
    InMemoryPlaybookVersionRepository,
)
from playbook.infrastructure.workers.playbook_workers import PlaybookScheduler

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from playbook.domain.repositories.i_playbook_repositories import (
        IAutomationPolicyRepository,
        IPlaybookRepository,
        IPlaybookTestResultRepository,
        IPlaybookVersionRepository,
    )


class PlaybookContainer:
    playbooks: IPlaybookRepository
    versions: IPlaybookVersionRepository
    tests: IPlaybookTestResultRepository
    policies: IAutomationPolicyRepository

    def __init__(
        self, session_factory: async_sessionmaker[AsyncSession] | None = None
    ) -> None:
        if session_factory is not None:
            from playbook.infrastructure.persistence.postgres_repositories import (
                PgAutomationPolicyRepository,
                PgPlaybookRepository,
                PgPlaybookTestResultRepository,
                PgPlaybookVersionRepository,
            )

            self.playbooks = PgPlaybookRepository(session_factory)
            self.versions = PgPlaybookVersionRepository(session_factory)
            self.tests = PgPlaybookTestResultRepository(session_factory)
            self.policies = PgAutomationPolicyRepository(session_factory)
        else:
            self.playbooks = InMemoryPlaybookRepository()
            self.versions = InMemoryPlaybookVersionRepository()
            self.tests = InMemoryPlaybookTestResultRepository()
            self.policies = InMemoryAutomationPolicyRepository()
        self.event_sink: list[object] = []
        self.kill_switch_log: list[dict[str, object]] = []
        self.metrics = OperationalMetricsStore()
        self.app = PlaybookApplicationService(
            self.playbooks,
            self.versions,
            self.tests,
            self.policies,
            self.event_sink,
            self.kill_switch_log,
        )
        self.scheduler = PlaybookScheduler()

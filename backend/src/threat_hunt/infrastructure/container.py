from __future__ import annotations

from typing import TYPE_CHECKING

from threat_hunt.application.services.hunt_application_service import HuntApplicationService
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter
from threat_hunt.infrastructure.persistence.in_memory_repositories import (
    InMemoryThreatHuntCandidateRepository,
    InMemoryThreatHuntConfigurationRepository,
)
from threat_hunt.infrastructure.workers.hunt_workers import HuntScheduler, ThreatHuntCandidateWorker

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from threat_hunt.domain.repositories.i_repositories import (
        IThreatHuntCandidateRepository,
        IThreatHuntConfigurationRepository,
    )


class ThreatHuntContainer:
    candidates: IThreatHuntCandidateRepository
    configs: IThreatHuntConfigurationRepository

    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> None:
        if session_factory is not None:
            from threat_hunt.infrastructure.persistence.postgres_repositories import (
                PgThreatHuntCandidateRepository,
                PgThreatHuntConfigurationRepository,
            )

            self.candidates = PgThreatHuntCandidateRepository(session_factory)
            self.configs = PgThreatHuntConfigurationRepository(session_factory)
        else:
            self.candidates = InMemoryThreatHuntCandidateRepository()
            self.configs = InMemoryThreatHuntConfigurationRepository()
        self.llm = InMemoryHuntLLMAdapter()
        self.event_sink: list[object] = []
        self.app = HuntApplicationService(self.candidates, self.configs, self.event_sink)
        self.candidate_worker = ThreatHuntCandidateWorker(self.app)
        self.scheduler = HuntScheduler(self.candidate_worker)

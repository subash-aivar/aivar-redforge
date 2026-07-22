from __future__ import annotations

from threat_hunt.application.services.hunt_application_service import HuntApplicationService
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter
from threat_hunt.infrastructure.persistence.in_memory_repositories import (
    InMemoryThreatHuntCandidateRepository,
    InMemoryThreatHuntConfigurationRepository,
)
from threat_hunt.infrastructure.workers.hunt_workers import HuntScheduler, ThreatHuntCandidateWorker


class ThreatHuntContainer:
    def __init__(self) -> None:
        self.candidates = InMemoryThreatHuntCandidateRepository()
        self.configs = InMemoryThreatHuntConfigurationRepository()
        self.llm = InMemoryHuntLLMAdapter()
        self.event_sink: list[object] = []
        self.app = HuntApplicationService(self.candidates, self.configs, self.event_sink)
        self.candidate_worker = ThreatHuntCandidateWorker(self.app)
        self.scheduler = HuntScheduler(self.candidate_worker)

from __future__ import annotations

from playbook.application.services.playbook_application_service import PlaybookApplicationService
from playbook.infrastructure.observability.metrics_store import OperationalMetricsStore
from playbook.infrastructure.persistence.in_memory_repositories import (
    InMemoryAutomationPolicyRepository,
    InMemoryPlaybookRepository,
    InMemoryPlaybookTestResultRepository,
    InMemoryPlaybookVersionRepository,
)
from playbook.infrastructure.workers.playbook_workers import PlaybookScheduler


class PlaybookContainer:
    def __init__(self) -> None:
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

from __future__ import annotations

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


class LessonsLearnedContainer:
    def __init__(self) -> None:
        self.ll_repo = InMemoryLessonsLearnedRepository()
        self.report_repo = InMemoryPostIncidentReportRepository()
        self.bus = InMemoryCampaignRetargetingEventBus()
        self.store = InMemoryReportArtifactStore()
        self.delivery = InMemoryPostIncidentReportDeliveryPort()
        self.app = LessonsApplicationService(
            self.ll_repo, self.report_repo, self.bus, self.store, self.delivery
        )

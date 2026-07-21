"""DI container for remediation_impact Phase 4."""

from __future__ import annotations

from typing import TYPE_CHECKING

from remediation_impact.application.services.exposure_reduction_plan_service import (
    ExposureReductionPlanService,
)
from remediation_impact.infrastructure.acl.exposure_score_query_adapter import (
    StaticExposureScoreQueryAdapter,
)
from remediation_impact.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from remediation_impact.infrastructure.persistence.in_memory_plan_repository import (
    InMemoryExposureReductionPlanRepository,
)
from remediation_impact.infrastructure.workers.simulation_worker import (
    RemediationSimulationWorker,
)

if TYPE_CHECKING:
    from remediation_impact.application.ports.i_exposure_score_query_port import (
        IExposureScoreQueryPort,
    )
    from remediation_impact.domain.repositories.i_exposure_reduction_plan_repository import (
        IExposureReductionPlanRepository,
    )


class RemediationImpactContainer:
    def __init__(
        self,
        *,
        repo: IExposureReductionPlanRepository | None = None,
        score_port: IExposureScoreQueryPort | None = None,
    ) -> None:
        self.repo = repo or InMemoryExposureReductionPlanRepository()
        self.event_publisher = StructlogEventPublisher()
        self.score_port = score_port or StaticExposureScoreQueryAdapter()
        self.plan_service = ExposureReductionPlanService(
            self.repo, self.event_publisher, self.score_port
        )
        self.simulation_worker = RemediationSimulationWorker(self.plan_service)

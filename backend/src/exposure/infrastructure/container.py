"""DI container for exposure Phase 1-4."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure.application.services.exposure_app_service import ExposureApplicationService
from exposure.application.services.exposure_scope_service import ExposureScopeService
from exposure.application.services.ingestion_app_service import (
    ExposureSignalIngestionService,
)
from exposure.application.services.score_pipeline_service import (
    ExposureScoreComputationWorker,
    RecomputationDebouncerService,
    RecomputationDispatcherService,
)
from exposure.application.services.threat_actor_match_sync_service import (
    ThreatActorMatchSyncService,
)
from exposure.application.services.threat_intelligence_query_service import (
    ThreatIntelligenceQueryService,
)
from exposure.infrastructure.acl.business_impact_query_adapter import (
    StubBusinessImpactQueryAdapter,
)
from exposure.infrastructure.acl.degraded_adapters import (
    StubAIRiskQueryAdapter,
    StubCloudExposureQueryAdapter,
    StubDetectionCoverageQueryAdapter,
    StubVulnerabilityQueryAdapter,
)
from exposure.infrastructure.acl.threat_intelligence_m21_adapter import (
    ThreatIntelligenceM21Adapter,
)
from exposure.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from exposure.infrastructure.events.threat_actor_targeting_subscriber import (
    ThreatActorTargetingSubscriber,
)
from exposure.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)
from exposure.infrastructure.repositories.threat_actor_match_cache_repository import (
    InMemoryThreatActorMatchCacheRepository,
)
from exposure.infrastructure.scheduler.threat_actor_poll_scheduler import (
    ThreatActorPollScheduler,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from exposure.application.ports.i_unit_of_work import IUnitOfWork
    from exposure.domain.ports.i_ai_risk_query_port import IAIRiskQueryPort
    from exposure.domain.ports.i_business_impact_query_port import IBusinessImpactQueryPort
    from exposure.domain.ports.i_cloud_exposure_query_port import ICloudExposureQueryPort
    from exposure.domain.ports.i_detection_coverage_query_port import (
        IDetectionCoverageQueryPort,
    )
    from exposure.domain.ports.i_threat_intelligence_query_port import (
        IThreatIntelligenceQueryPort,
    )
    from exposure.domain.ports.i_vulnerability_query_port import IVulnerabilityQueryPort
    from exposure.infrastructure.repositories.threat_actor_match_cache_repository import (
        IThreatActorMatchCacheRepository,
    )


class ExposureContainer:
    """Composition root.

    Intentionally process-local InMemory UoW by default (M29-M31 pattern).
    ACL ports default to seedable stubs until live upstream adapters are injected.
    """

    def __init__(
        self,
        *,
        uow_factory: Callable[[], IUnitOfWork] | None = None,
        vulnerability_port: IVulnerabilityQueryPort | None = None,
        cloud_port: ICloudExposureQueryPort | None = None,
        detection_port: IDetectionCoverageQueryPort | None = None,
        ai_risk_port: IAIRiskQueryPort | None = None,
        threat_port: IThreatIntelligenceQueryPort | None = None,
        cache_repo: IThreatActorMatchCacheRepository | None = None,
        business_impact_port: IBusinessImpactQueryPort | None = None,
    ) -> None:
        shared = InMemoryUnitOfWork()

        def default_factory() -> IUnitOfWork:
            return shared

        self._uow_factory = uow_factory or default_factory
        self.event_publisher = StructlogEventPublisher()
        self.vulnerability_port = vulnerability_port or StubVulnerabilityQueryAdapter()
        self.cloud_port = cloud_port or StubCloudExposureQueryAdapter()
        self.detection_port = detection_port or StubDetectionCoverageQueryAdapter()
        self.ai_risk_port = ai_risk_port or StubAIRiskQueryAdapter()
        self.threat_port = threat_port or ThreatIntelligenceM21Adapter()
        self.cache_repo = cache_repo or InMemoryThreatActorMatchCacheRepository()
        self.ingestion = ExposureSignalIngestionService(self._uow_factory, self.event_publisher)
        self.exposure_service = ExposureApplicationService(self._uow_factory, self.event_publisher)
        self.debouncer = RecomputationDebouncerService(self._uow_factory)
        self.dispatcher = RecomputationDispatcherService(self._uow_factory)
        self.score_worker = ExposureScoreComputationWorker(self._uow_factory, self.event_publisher)
        self.threat_sync = ThreatActorMatchSyncService(
            self._uow_factory,
            self.event_publisher,
            self.threat_port,
            self.cache_repo,
        )
        self.threat_query = ThreatIntelligenceQueryService(self.cache_repo)
        self.threat_subscriber = ThreatActorTargetingSubscriber(self.threat_sync)
        self.threat_poll_scheduler = ThreatActorPollScheduler(self.threat_sync)
        self.business_impact_port = business_impact_port or StubBusinessImpactQueryAdapter()
        self.scope_service = ExposureScopeService(
            self._uow_factory,
            self.cache_repo,
            self.business_impact_port,
        )

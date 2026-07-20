"""DetectionContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.application.projections.detection_projection_service import (
    DetectionProjectionService,
)
from detection.application.projections.projection_coordinator import ProjectionCoordinator
from detection.application.projections.projection_publisher import ProjectionPublisher
from detection.application.projections.read_model_store import InMemoryReadModelStore
from detection.application.services.correlation_coordinator import CorrelationCoordinator
from detection.application.services.correlation_publisher import CorrelationPublisher
from detection.application.services.execution_finding_application_service import (
    ExecutionFindingApplicationService,
)
from detection.application.services.phase4_application_service import (
    PackExceptionEvidenceApplicationService,
)
from detection.application.services.platform_orchestration_service import (
    PlatformOrchestrationService,
)
from detection.application.services.platform_validation_service import (
    PlatformValidationService,
)
from detection.application.services.projection_application_service import (
    ProjectionApplicationService,
)
from detection.application.services.rule_application_service import RuleApplicationService
from detection.application.services.telemetry_application_service import (
    TelemetryApplicationService,
)
from detection.domain.providers.registry import TelemetryProviderRegistry
from detection.domain.services.correlation import CorrelationService
from detection.infrastructure.acl.degraded_adapters import (
    BehavioralSignalAdapter,
    CloudContextAdapter,
    ComplianceAdapter,
    InventoryAdapter,
    ThreatIntelAdapter,
    VulnerabilityContextAdapter,
)
from detection.infrastructure.blob.in_memory_evidence_blob_store import (
    InMemoryEvidenceBlobStore,
)
from detection.infrastructure.events.structlog_event_publisher import StructlogEventPublisher
from detection.infrastructure.graph.in_memory_security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from detection.infrastructure.persistence.unit_of_work import make_detection_uow_factory
from detection.infrastructure.providers.telemetry_query_port import RegistryTelemetryQueryPort

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from detection.application.ports.i_event_publisher import IEventPublisher
    from detection.application.projections.read_model_store import IReadModelStore
    from detection.domain.ports.correlation_ports import (
        IBehavioralSignalAdapter,
        ICloudContextAdapter,
        IComplianceAdapter,
        IInventoryAdapter,
        IThreatIntelAdapter,
        IVulnerabilityContextAdapter,
    )
    from detection.domain.ports.i_evidence_blob_store import IEvidenceBlobStore
    from detection.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


class DetectionContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher | None = None,
        provider_registry: TelemetryProviderRegistry | None = None,
        *,
        inventory_adapter: IInventoryAdapter | None = None,
        cloud_adapter: ICloudContextAdapter | None = None,
        vulnerability_adapter: IVulnerabilityContextAdapter | None = None,
        threat_intel_adapter: IThreatIntelAdapter | None = None,
        compliance_adapter: IComplianceAdapter | None = None,
        behavioral_adapter: IBehavioralSignalAdapter | None = None,
        blob_store: IEvidenceBlobStore | None = None,
        graph_port: ISecurityGraphWritePort | None = None,
        read_model_store: IReadModelStore | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.event_publisher: IEventPublisher = event_publisher or StructlogEventPublisher()
        self.provider_registry = provider_registry or TelemetryProviderRegistry()
        uow_factory = make_detection_uow_factory(session_factory)
        self.query_port = RegistryTelemetryQueryPort(uow_factory, self.provider_registry)
        self.rule_service = RuleApplicationService(uow_factory, self.event_publisher)
        self.telemetry_service = TelemetryApplicationService(
            uow_factory,
            self.event_publisher,
            self.provider_registry,
            self.query_port,
        )
        self.execution_finding_service = ExecutionFindingApplicationService(
            uow_factory,
            self.event_publisher,
        )

        self.inventory_adapter = inventory_adapter or InventoryAdapter()
        self.cloud_adapter = cloud_adapter or CloudContextAdapter()
        self.vulnerability_adapter = vulnerability_adapter or VulnerabilityContextAdapter()
        self.threat_intel_adapter = threat_intel_adapter or ThreatIntelAdapter()
        self.compliance_adapter = compliance_adapter or ComplianceAdapter()
        self.behavioral_adapter = behavioral_adapter or BehavioralSignalAdapter()
        self.blob_store = blob_store or InMemoryEvidenceBlobStore()

        self.correlation_service = CorrelationService(
            inventory=self.inventory_adapter,
            cloud=self.cloud_adapter,
            vulnerability=self.vulnerability_adapter,
            threat_intel=self.threat_intel_adapter,
            compliance=self.compliance_adapter,
            behavioral=self.behavioral_adapter,
        )
        self.correlation_publisher = CorrelationPublisher(self.event_publisher)
        self.correlation_coordinator = CorrelationCoordinator(
            uow_factory,
            self.correlation_service,
            self.correlation_publisher,
        )
        self.phase4_service = PackExceptionEvidenceApplicationService(
            uow_factory,
            self.event_publisher,
            self.blob_store,
        )

        # Phase 5 — projections / graph / platform
        self.graph_port = graph_port or InMemorySecurityGraphWriteAdapter()
        self.read_model_store = read_model_store or InMemoryReadModelStore()
        self.projection_publisher = ProjectionPublisher()
        self.detection_projection_service = DetectionProjectionService(
            self.read_model_store
        )
        self.projection_coordinator = ProjectionCoordinator(
            self.projection_publisher,
            self.detection_projection_service,
            self.graph_port,
        )
        self.platform_validation = PlatformValidationService(
            self.projection_coordinator,
            self.read_model_store,
        )
        self.projection_service = ProjectionApplicationService(
            self.projection_coordinator,
            self.read_model_store,
            self.platform_validation,
        )
        self.platform_orchestration = PlatformOrchestrationService(
            rule_service=self.rule_service,
            telemetry_service=self.telemetry_service,
            execution_finding_service=self.execution_finding_service,
            phase4_service=self.phase4_service,
            correlation_coordinator=self.correlation_coordinator,
            projection_service=self.projection_service,
            projection_coordinator=self.projection_coordinator,
        )

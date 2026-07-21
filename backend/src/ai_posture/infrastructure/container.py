"""DI container for ai_posture Phase 1-5."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_agent_governance.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork as AgentInMemoryUnitOfWork,
)
from ai_posture.application.projections.projection_service import M31ProjectionService
from ai_posture.application.projections.read_model_store import InMemoryReadModelStore
from ai_posture.application.projections.rebuild_service import ProjectionRebuildService
from ai_posture.application.projections.security_graph_adapter import (
    InMemorySecurityGraphAdapter,
)
from ai_posture.application.queries.report_query_handlers import ReportQueryHandler
from ai_posture.application.services.ai_system_asset_service import (
    AISystemAssetApplicationService,
)
from ai_posture.application.services.compliance_mapping_app_service import (
    ComplianceMappingApplicationService,
)
from ai_posture.application.services.report_export_service import ReportExportService
from ai_posture.application.services.risk_scoring_app_service import (
    RiskScoringApplicationService,
)
from ai_posture.application.services.shadow_ai_alert_service import (
    ShadowAIAlertApplicationService,
)
from ai_posture.application.services.threat_assessment_app_service import (
    ThreatAssessmentApplicationService,
)
from ai_posture.infrastructure.acl.cross_context_adapters import (
    InProcessAgentDeviationStatsAdapter,
    InProcessDiscoveryScanFactsAdapter,
    InProcessProvenanceIntegrityAdapter,
)
from ai_posture.infrastructure.acl.degraded_adapters import (
    StubCloudDiscoveryQueryAdapter,
    StubDetectionRuleQueryAdapter,
    StubInventoryQueryAdapter,
)
from ai_posture.infrastructure.acl.phase5_adapters import LocalComplianceCatalogAdapter
from ai_posture.infrastructure.events.projection_bridging_publisher import (
    ProjectionBridgingPublisher,
)
from ai_posture.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)
from ai_supply_chain.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork as SupplyInMemoryUnitOfWork,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_agent_governance.application.ports.i_unit_of_work import (
        IUnitOfWork as AgentUoW,
    )
    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
    from ai_posture.domain.ports.i_agent_deviation_stats_port import (
        IAgentDeviationStatsPort,
    )
    from ai_posture.domain.ports.i_cloud_discovery_query_port import ICloudDiscoveryQueryPort
    from ai_posture.domain.ports.i_compliance_query_port import IComplianceQueryPort
    from ai_posture.domain.ports.i_detection_rule_query_port import IDetectionRuleQueryPort
    from ai_posture.domain.ports.i_discovery_scan_facts_port import IDiscoveryScanFactsPort
    from ai_posture.domain.ports.i_inventory_query_port import IInventoryQueryPort
    from ai_posture.domain.ports.i_provenance_integrity_query_port import (
        IProvenanceIntegrityQueryPort,
    )
    from ai_posture.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
    from ai_supply_chain.application.ports.i_unit_of_work import (
        IUnitOfWork as SupplyUoW,
    )


class AIPostureContainer:
    """Composition root for ai_posture.

    Phase 5 production defaults:
    - Local compliance catalog (M24 fallback)
    - In-process ACL adapters over sibling supply-chain / agent-governance UoWs
    - Process-local in-memory UoW, read-model store, and security graph
      (same pattern as M29/M30 BC containers; PG repos inject via ``uow_factory`` /
      port overrides at the platform composition root)
    """

    def __init__(
        self,
        *,
        uow_factory: Callable[[], IUnitOfWork] | None = None,
        inventory_port: IInventoryQueryPort | None = None,
        cloud_port: ICloudDiscoveryQueryPort | None = None,
        detection_port: IDetectionRuleQueryPort | None = None,
        compliance_port: IComplianceQueryPort | None = None,
        provenance_port: IProvenanceIntegrityQueryPort | None = None,
        agent_port: IAgentDeviationStatsPort | None = None,
        discovery_port: IDiscoveryScanFactsPort | None = None,
        graph_port: ISecurityGraphWritePort | None = None,
        supply_uow_factory: Callable[[], SupplyUoW] | None = None,
        agent_uow_factory: Callable[[], AgentUoW] | None = None,
    ) -> None:
        shared_uow = InMemoryUnitOfWork()

        def default_factory() -> IUnitOfWork:
            return shared_uow

        shared_supply = SupplyInMemoryUnitOfWork()

        def default_supply_factory() -> SupplyUoW:
            return shared_supply

        shared_agent = AgentInMemoryUnitOfWork()

        def default_agent_factory() -> AgentUoW:
            return shared_agent

        self._uow_factory = uow_factory or default_factory
        self._supply_uow_factory = supply_uow_factory or default_supply_factory
        self._agent_uow_factory = agent_uow_factory or default_agent_factory
        self.read_model_store = InMemoryReadModelStore()
        self.graph = graph_port or InMemorySecurityGraphAdapter()
        self.projections = M31ProjectionService(self.read_model_store, self.graph)
        self.event_publisher = ProjectionBridgingPublisher(self.projections)
        # Intentionally degraded until live M22/M26/M28 adapters are injected.
        self.inventory_port = inventory_port or StubInventoryQueryAdapter()
        self.cloud_port = cloud_port or StubCloudDiscoveryQueryAdapter()
        self.detection_port = detection_port or StubDetectionRuleQueryAdapter()
        # Phase 5 production catalog (local classification seed / M24 fallback).
        self.compliance_port = compliance_port or LocalComplianceCatalogAdapter()
        # Phase 5 production cross-BC ACL defaults (overridable for tests/ops).
        self.provenance_port = provenance_port or InProcessProvenanceIntegrityAdapter(
            self._supply_uow_factory
        )
        self.agent_port = agent_port or InProcessAgentDeviationStatsAdapter(self._agent_uow_factory)
        self.discovery_port = discovery_port or InProcessDiscoveryScanFactsAdapter(
            self._supply_uow_factory
        )
        self.asset_service = AISystemAssetApplicationService(
            self._uow_factory, self.event_publisher, self.inventory_port
        )
        self.alert_service = ShadowAIAlertApplicationService(
            self._uow_factory, self.event_publisher
        )
        self.threat_service = ThreatAssessmentApplicationService(
            self._uow_factory,
            self.event_publisher,
            self.cloud_port,
            self.detection_port,
        )
        self.compliance_service = ComplianceMappingApplicationService(
            self._uow_factory,
            self.event_publisher,
            self.compliance_port,
            self.provenance_port,
            self.agent_port,
        )
        self.risk_service = RiskScoringApplicationService(
            self._uow_factory,
            self.event_publisher,
            provenance_port=self.provenance_port,
            agent_port=self.agent_port,
            gap_count_fn=self.compliance_service.gap_count_for_asset,
        )
        self.rebuild_service = ProjectionRebuildService(
            self._uow_factory,
            self.read_model_store,
            self.projections,
            self.provenance_port,
            self.agent_port,
            self.discovery_port,
        )
        self.report_queries = ReportQueryHandler(self.read_model_store)
        self.export_service = ReportExportService(self.report_queries)

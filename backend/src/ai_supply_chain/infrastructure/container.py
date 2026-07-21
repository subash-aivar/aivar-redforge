from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.application.queries.supply_chain_query_handlers import (
    SupplyChainQueryHandler,
)
from ai_supply_chain.application.services.discovery_app_service import (
    DiscoveryApplicationService,
)
from ai_supply_chain.application.services.mbom_app_service import MBOMApplicationService
from ai_supply_chain.application.services.provenance_app_service import (
    ProvenanceApplicationService,
)
from ai_supply_chain.infrastructure.acl.degraded_adapters import (
    RecordingInventoryMatchAdapter,
    RecordingShadowAlertRaiseAdapter,
    StubVulnerabilityQueryAdapter,
)
from ai_supply_chain.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from ai_supply_chain.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)
from ai_supply_chain.infrastructure.providers.discovery_providers import (
    CloudAuditLogKubernetesAdmissionAdapter,
    InMemoryCloudAIServiceProvider,
    InMemoryHuggingFaceHubProvider,
    InMemoryModelRegistryProvider,
    ThinMCPServerDiscoveryAdapter,
)
from ai_supply_chain.infrastructure.providers.hash_and_signature_adapters import (
    ProviderSignatureVerificationAdapter,
    StreamingArtifactHashAdapter,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork


class SupplyChainContainer:
    def __init__(self, *, uow_factory: Callable[[], IUnitOfWork] | None = None) -> None:
        shared = InMemoryUnitOfWork()

        def default_factory() -> IUnitOfWork:
            return shared

        self._uow_factory = uow_factory or default_factory
        self.event_publisher = StructlogEventPublisher()
        self.hash_port = StreamingArtifactHashAdapter()
        self.signature_port = ProviderSignatureVerificationAdapter()
        self.huggingface = InMemoryHuggingFaceHubProvider()
        self.cloud = InMemoryCloudAIServiceProvider()
        self.registry = InMemoryModelRegistryProvider()
        self.mcp = ThinMCPServerDiscoveryAdapter()
        self.k8s = CloudAuditLogKubernetesAdmissionAdapter()
        self.vulnerability = StubVulnerabilityQueryAdapter()
        self.inventory_match = RecordingInventoryMatchAdapter()
        self.shadow_alerts = RecordingShadowAlertRaiseAdapter()
        self.provenance_service = ProvenanceApplicationService(
            self._uow_factory,
            self.event_publisher,
            self.hash_port,
            self.signature_port,
        )
        self.mbom_service = MBOMApplicationService(
            self._uow_factory, self.event_publisher, self.vulnerability
        )
        self.discovery_service = DiscoveryApplicationService(
            self._uow_factory,
            self.event_publisher,
            self.huggingface,
            self.cloud,
            self.registry,
            self.mcp,
            self.k8s,
            self.inventory_match,
            self.shadow_alerts,
        )
        self.query_handler = SupplyChainQueryHandler(self._uow_factory)

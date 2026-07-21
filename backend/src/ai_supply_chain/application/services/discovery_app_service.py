from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ai_supply_chain.application._auth import require_at_least
from ai_supply_chain.application.dtos.supply_chain_dtos import DiscoveryScanRunDTO
from ai_supply_chain.domain.services.ai_discovery_scan_coordinator import (
    AIDiscoveryScanCoordinator,
)
from ai_supply_chain.domain.value_objects.enums import AIPostureRole, DiscoverySourceType
from ai_supply_chain.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_supply_chain.application.commands.supply_chain_commands import (
        RunDiscoveryScanCommand,
    )
    from ai_supply_chain.application.ports.i_event_publisher import IEventPublisher
    from ai_supply_chain.application.ports.i_unit_of_work import IUnitOfWork
    from ai_supply_chain.domain.ports.i_cloud_ai_service_provider_port import (
        ICloudAIServiceProviderPort,
    )
    from ai_supply_chain.domain.ports.i_huggingface_hub_provider_port import (
        IHuggingFaceHubProviderPort,
    )
    from ai_supply_chain.domain.ports.i_inventory_match_port import IInventoryMatchPort
    from ai_supply_chain.domain.ports.i_kubernetes_admission_query_port import (
        IKubernetesAdmissionQueryPort,
    )
    from ai_supply_chain.domain.ports.i_mcp_server_discovery_port import (
        IMCPServerDiscoveryPort,
    )
    from ai_supply_chain.domain.ports.i_model_registry_provider_port import (
        IModelRegistryProviderPort,
    )
    from ai_supply_chain.domain.ports.i_shadow_alert_raise_port import (
        IShadowAlertRaisePort,
    )


class DiscoveryApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        huggingface: IHuggingFaceHubProviderPort,
        cloud: ICloudAIServiceProviderPort,
        registry: IModelRegistryProviderPort,
        mcp: IMCPServerDiscoveryPort,
        k8s: IKubernetesAdmissionQueryPort,
        inventory: IInventoryMatchPort,
        shadow_alerts: IShadowAlertRaisePort,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._coordinator = AIDiscoveryScanCoordinator(
            huggingface, cloud, registry, mcp, k8s, inventory, shadow_alerts
        )

    async def run_scan(self, cmd: RunDiscoveryScanCommand) -> DiscoveryScanRunDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        sources = [DiscoverySourceType(s) for s in cmd.sources] or list(DiscoverySourceType)
        async with self._uow_factory() as uow:
            settings = await uow.settings.get(tenant)
            run = await self._coordinator.run_scan(
                tenant, sources, list(cmd.cloud_accounts), settings, now
            )
            await uow.scans.save(run)
            await uow.commit()
            await self._publisher.publish_batch(run.pop_events())
        return DiscoveryScanRunDTO(
            scan_run_id=str(run.scan_run_id),
            state=run.state.value,
            partial=run.partial,
            discovered_count=len(run.discovered),
            unmatched_count=len(run.unmatched),
            failed_partitions=list(run.failed_partitions),
            api_calls_used=run.api_calls_used,
        )

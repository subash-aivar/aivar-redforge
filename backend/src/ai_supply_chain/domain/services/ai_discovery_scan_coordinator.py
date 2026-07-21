"""AIDiscoveryScanCoordinator — multi-source discovery with partition isolation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.domain.aggregates.ai_discovery_scan_run import AIDiscoveryScanRun
from ai_supply_chain.domain.value_objects.enums import (
    DiscoverySourceType,
    KubernetesCloudProvider,
)
from ai_supply_chain.domain.value_objects.identifiers import AIDiscoveryScanRunId

if TYPE_CHECKING:
    from datetime import datetime

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
    from ai_supply_chain.domain.repositories.i_tenant_verification_settings_repository import (
        TenantVerificationSettings,
    )
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class AIDiscoveryScanCoordinator:
    def __init__(
        self,
        huggingface: IHuggingFaceHubProviderPort,
        cloud: ICloudAIServiceProviderPort,
        registry: IModelRegistryProviderPort,
        mcp: IMCPServerDiscoveryPort,
        k8s: IKubernetesAdmissionQueryPort,
        inventory: IInventoryMatchPort,
        shadow_alerts: IShadowAlertRaisePort,
    ) -> None:
        self._hf = huggingface
        self._cloud = cloud
        self._registry = registry
        self._mcp = mcp
        self._k8s = k8s
        self._inventory = inventory
        self._shadow = shadow_alerts

    async def run_scan(
        self,
        tenant_id: TenantId,
        sources: list[DiscoverySourceType],
        cloud_accounts: list[str],
        settings: TenantVerificationSettings,
        now: datetime,
    ) -> AIDiscoveryScanRun:
        run = AIDiscoveryScanRun.start(AIDiscoveryScanRunId.generate(), tenant_id, sources, now)
        for source in sources:
            partition = source.value
            try:
                services = await self._collect(source, tenant_id, cloud_accounts)
            except _PartialPartitionError as exc:
                services = exc.results
                for err in exc.errors:
                    run.record_partition_failure(f"{partition}:{err}")
            except Exception as exc:
                run.record_partition_failure(f"{partition}:{exc}")
                continue
            for svc in services:
                if run.api_calls_used >= settings.max_api_calls_per_scan:
                    run.record_partition_failure(f"{partition}:api_budget_exhausted")
                    break
                matched = await self._inventory.has_matching_asset(tenant_id, svc)
                run.record_discovery(tenant_id, svc, matched=matched)
                if not matched:
                    await self._shadow.raise_for_unmatched(tenant_id, svc)
        run.complete(tenant_id, now)
        return run

    async def _collect(
        self,
        source: DiscoverySourceType,
        tenant_id: TenantId,
        cloud_accounts: list[str],
    ) -> list[DiscoveredAIService]:
        if source == DiscoverySourceType.HUGGING_FACE_HUB:
            return await self._hf.list_models(tenant_id)
        if source == DiscoverySourceType.MODEL_REGISTRY_PROTOCOL:
            return await self._registry.list_registered_models(tenant_id)
        if source == DiscoverySourceType.MCP_SERVER_DISCOVERY:
            return await self._mcp.list_mcp_servers(tenant_id)
        if source == DiscoverySourceType.CLOUD_PROVIDER_SCAN:
            results: list[DiscoveredAIService] = []
            errors: list[str] = []
            for account in cloud_accounts[:5]:
                try:
                    results.extend(await self._cloud.list_ai_services(tenant_id, account))
                except Exception as exc:
                    errors.append(f"{account}:{exc}")
            if errors and not results:
                raise RuntimeError(";".join(errors))
            if errors:
                # Surface partial account failures via exception marker for coordinator
                raise _PartialPartitionError(results, errors)
            return results
        if source == DiscoverySourceType.KUBERNETES_ADMISSION:
            results = []
            for account in cloud_accounts:
                for provider in KubernetesCloudProvider:
                    results.extend(
                        await self._k8s.list_ai_workloads_from_audit_logs(
                            tenant_id, provider, account
                        )
                    )
            return results
        return []


class _PartialPartitionError(Exception):
    def __init__(self, results: list[DiscoveredAIService], errors: list[str]) -> None:
        self.results = results
        self.errors = errors
        super().__init__(",".join(errors))

"""Discovery provider adapters — cloud / HF / registry / MCP / K8s audit logs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_supply_chain.domain.ports.i_cloud_ai_service_provider_port import (
    ICloudAIServiceProviderPort,
)
from ai_supply_chain.domain.ports.i_huggingface_hub_provider_port import (
    HuggingFaceModelMetadata,
    IHuggingFaceHubProviderPort,
)
from ai_supply_chain.domain.ports.i_kubernetes_admission_query_port import (
    IKubernetesAdmissionQueryPort,
)
from ai_supply_chain.domain.ports.i_mcp_server_discovery_port import IMCPServerDiscoveryPort
from ai_supply_chain.domain.ports.i_model_registry_provider_port import (
    IModelRegistryProviderPort,
)
from ai_supply_chain.domain.value_objects.enums import (
    KubernetesCloudProvider,
    MBOMComponentType,
)
from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    ArtifactDescriptor,
    DiscoveredAIService,
    MBOMComponent,
)

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId


class InMemoryHuggingFaceHubProvider(IHuggingFaceHubProviderPort):
    def __init__(self) -> None:
        self.models: dict[str, list[DiscoveredAIService]] = {}
        self.metadata: dict[str, HuggingFaceModelMetadata] = {}
        self.fail = False

    async def list_models(self, tenant_id: TenantId) -> list[DiscoveredAIService]:
        if self.fail:
            raise RuntimeError("huggingface unavailable")
        return list(self.models.get(str(tenant_id), []))

    async def get_model_metadata(
        self, tenant_id: TenantId, model_id: str
    ) -> HuggingFaceModelMetadata:
        return self.metadata[model_id]


class InMemoryCloudAIServiceProvider(ICloudAIServiceProviderPort):
    def __init__(self) -> None:
        self.by_account: dict[str, list[DiscoveredAIService]] = {}
        self.fail_accounts: set[str] = set()

    async def list_ai_services(
        self, tenant_id: TenantId, cloud_account: str
    ) -> list[DiscoveredAIService]:
        if cloud_account in self.fail_accounts:
            raise RuntimeError(f"cloud provider 503 for {cloud_account}")
        return list(self.by_account.get(cloud_account, []))


class InMemoryModelRegistryProvider(IModelRegistryProviderPort):
    def __init__(self) -> None:
        self.models: list[DiscoveredAIService] = []
        self.artifacts: dict[str, ArtifactDescriptor] = {}
        self.components: dict[str, list[MBOMComponent]] = {}

    async def list_registered_models(self, tenant_id: TenantId) -> list[DiscoveredAIService]:
        return list(self.models)

    async def get_artifact(self, tenant_id: TenantId, registry_id: str) -> ArtifactDescriptor:
        return self.artifacts[registry_id]

    async def get_components(self, tenant_id: TenantId, registry_id: str) -> list[MBOMComponent]:
        return list(self.components.get(registry_id, []))


class ThinMCPServerDiscoveryAdapter(IMCPServerDiscoveryPort):
    """Thin versioned MCP adapter — protocol details isolated here."""

    PROTOCOL_VERSION = "mcp-discovery-v1"

    def __init__(self) -> None:
        self.servers: list[DiscoveredAIService] = []

    async def list_mcp_servers(self, tenant_id: TenantId) -> list[DiscoveredAIService]:
        return list(self.servers)


class CloudAuditLogKubernetesAdmissionAdapter(IKubernetesAdmissionQueryPort):
    """Read-only EKS/GKE/AKS audit log ingestion — No admission webhook."""

    def __init__(self) -> None:
        self.workloads: dict[tuple[str, str, str], list[DiscoveredAIService]] = {}

    def seed(
        self,
        provider: KubernetesCloudProvider,
        cloud_account: str,
        services: list[DiscoveredAIService],
    ) -> None:
        self.workloads[(provider.value, cloud_account, "tenant")] = services

    async def list_ai_workloads_from_audit_logs(
        self,
        tenant_id: TenantId,
        provider: KubernetesCloudProvider,
        cloud_account: str,
    ) -> list[DiscoveredAIService]:
        # Cloud audit log read path (CloudWatch / Cloud Audit Logs / Azure Monitor)
        key = (provider.value, cloud_account, "tenant")
        seeded = self.workloads.get(key)
        if seeded is not None:
            return list(seeded)
        # Default empty — read-only; never mutates cluster state
        return []


def sample_base_component(name: str = "llama-base") -> MBOMComponent:
    return MBOMComponent(
        component_type=MBOMComponentType.BASE_MODEL,
        name=name,
        version="1.0.0",
        source="huggingface",
        checksum="abc",
    )

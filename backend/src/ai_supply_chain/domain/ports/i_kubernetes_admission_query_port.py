from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.enums import KubernetesCloudProvider
    from ai_supply_chain.domain.value_objects.identifiers import TenantId
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class IKubernetesAdmissionQueryPort(ABC):
    """Read-only cloud audit log ingestion (EKS/GKE/AKS). No admission webhook."""

    @abstractmethod
    async def list_ai_workloads_from_audit_logs(
        self,
        tenant_id: TenantId,
        provider: KubernetesCloudProvider,
        cloud_account: str,
    ) -> list[DiscoveredAIService]: ...

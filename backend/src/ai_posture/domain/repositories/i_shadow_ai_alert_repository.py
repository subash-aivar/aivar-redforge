"""IShadowAIAlertRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.aggregates.shadow_ai_alert import ShadowAIAlert
    from ai_posture.domain.value_objects.identifiers import ShadowAIAlertId, TenantId
    from ai_posture.domain.value_objects.posture_vos import DiscoveredServiceFingerprint


class IShadowAIAlertRepository(ABC):
    @abstractmethod
    async def save(self, alert: ShadowAIAlert) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, alert_id: ShadowAIAlertId, tenant_id: TenantId
    ) -> ShadowAIAlert | None: ...

    @abstractmethod
    async def find_open_by_tenant(self, tenant_id: TenantId) -> list[ShadowAIAlert]: ...

    @abstractmethod
    async def find_by_fingerprint(
        self, fingerprint: DiscoveredServiceFingerprint, tenant_id: TenantId
    ) -> ShadowAIAlert | None: ...

    @abstractmethod
    async def find_open_matching(
        self,
        tenant_id: TenantId,
        *,
        discovery_source: str | None = None,
        cloud_account: str | None = None,
        service_type: str | None = None,
    ) -> list[ShadowAIAlert]: ...

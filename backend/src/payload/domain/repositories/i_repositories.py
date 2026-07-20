"""Repository interfaces for the payload context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from payload.domain.aggregates.payload import Payload
    from payload.domain.aggregates.plugin_registration import PluginRegistration
    from payload.domain.value_objects.identifiers import PayloadId, PluginId, TenantId
    from payload.domain.value_objects.payload_vos import PayloadKey


class IPayloadRepository(ABC):
    @abstractmethod
    async def save(self, payload: Payload) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, payload_id: PayloadId, tenant_id: TenantId
    ) -> Payload | None: ...

    @abstractmethod
    async def find_by_key(
        self, payload_key: PayloadKey, tenant_id: TenantId
    ) -> Payload | None: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Payload]: ...


class IPluginRegistrationRepository(ABC):
    @abstractmethod
    async def save(self, plugin: PluginRegistration) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, plugin_id: PluginId, tenant_id: TenantId
    ) -> PluginRegistration | None: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[PluginRegistration]: ...

"""Tenant settings for discovery-only mode."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.value_objects.identifiers import TenantId


class ITenantSettingsRepository(ABC):
    @abstractmethod
    async def is_discovery_only_mode(self, tenant_id: TenantId) -> bool: ...

    @abstractmethod
    async def set_discovery_only_mode(self, tenant_id: TenantId, enabled: bool) -> None: ...

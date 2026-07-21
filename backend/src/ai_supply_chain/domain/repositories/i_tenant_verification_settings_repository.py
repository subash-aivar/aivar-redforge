from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    DEFAULT_SIZE_THRESHOLD_BYTES,
)

if TYPE_CHECKING:
    from ai_supply_chain.domain.value_objects.identifiers import TenantId


@dataclass
class TenantVerificationSettings:
    size_threshold_bytes: int = DEFAULT_SIZE_THRESHOLD_BYTES
    monthly_egress_budget_bytes: int = 500 * 1024 * 1024 * 1024
    egress_bytes_used: int = 0
    max_api_calls_per_scan: int = 1000
    max_concurrent_accounts: int = 5


class ITenantVerificationSettingsRepository(ABC):
    @abstractmethod
    async def get(self, tenant_id: TenantId) -> TenantVerificationSettings: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, settings: TenantVerificationSettings) -> None: ...

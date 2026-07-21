"""ICloudDiscoveryQueryPort — ACL to M26 (Phase 2 assessment signals)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId


@dataclass(frozen=True, slots=True)
class CloudSystemConfigSignals:
    query_rate_limiting_present: bool = False
    output_verbosity: str = "Standard"
    watermarking_present: bool = False
    sanitization_posture: str = "Unknown"
    input_surface: str = "UserFacingText"
    downstream_action_capability: str = "ReadOnly"


class ICloudDiscoveryQueryPort(ABC):
    @abstractmethod
    async def get_system_config_signals(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> CloudSystemConfigSignals: ...

"""Degraded ACL adapters — never import M22/M26/M28 domain types."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_posture.domain.exceptions.domain_exceptions import InventoryAssetNotFound
from ai_posture.domain.ports.i_asset_registration_port import IAssetRegistrationPort
from ai_posture.domain.ports.i_cloud_discovery_query_port import (
    CloudSystemConfigSignals,
    ICloudDiscoveryQueryPort,
)
from ai_posture.domain.ports.i_detection_rule_query_port import IDetectionRuleQueryPort
from ai_posture.domain.ports.i_inventory_query_port import IInventoryQueryPort
from ai_posture.domain.value_objects.posture_vos import AssetRef

if TYPE_CHECKING:
    from uuid import UUID

    from ai_posture.domain.value_objects.enums import AIThreatCategory
    from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId
    from ai_posture.domain.value_objects.posture_vos import DiscoveredServiceFingerprint


class StubInventoryQueryAdapter(IInventoryQueryPort):
    """Resolves known asset ids; enforces tenant match."""

    def __init__(self) -> None:
        self._known: dict[tuple[str, str], AssetRef] = {}

    def seed(self, asset_id: UUID, tenant_id: TenantId, asset_type: str = "AIAsset") -> None:
        self._known[(str(tenant_id), str(asset_id))] = AssetRef(asset_id, asset_type)

    async def resolve_asset_ref(self, asset_id: UUID, tenant_id: TenantId) -> AssetRef | None:
        key = (str(tenant_id), str(asset_id))
        # Cross-tenant probe: if asset exists under another tenant, hard error
        for (t, a), _ref in self._known.items():
            if a == str(asset_id) and t != str(tenant_id):
                raise InventoryAssetNotFound(str(asset_id))
        return self._known.get(key)


class StubAssetRegistrationAdapter(IAssetRegistrationPort):
    def __init__(self, inventory: StubInventoryQueryAdapter) -> None:
        self._inventory = inventory

    async def register_ai_asset_stub(
        self,
        tenant_id: TenantId,
        fingerprint: DiscoveredServiceFingerprint,
    ) -> AssetRef:
        asset_id = uuid4()
        ref = AssetRef(asset_id, "AIAsset")
        self._inventory.seed(asset_id, tenant_id)
        return ref


class StubCloudDiscoveryQueryAdapter(ICloudDiscoveryQueryPort):
    def __init__(self, signals: CloudSystemConfigSignals | None = None) -> None:
        self.signals = signals or CloudSystemConfigSignals()

    async def get_system_config_signals(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> CloudSystemConfigSignals:
        return self.signals


class StubDetectionRuleQueryAdapter(IDetectionRuleQueryPort):
    def __init__(self, *, has_rules: bool = False) -> None:
        self.has_rules = has_rules

    async def has_rules_for_category(self, category: AIThreatCategory, tenant_id: TenantId) -> bool:
        return self.has_rules

"""Event subscriber for M21 ThreatActorAssetClassTargetingUpdated (Phase 3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from exposure.application.services.threat_actor_match_sync_service import (
        ThreatActorMatchSyncService,
    )


class ThreatActorTargetingSubscriber:
    """Primary hybrid path — translates inbound event payload into sync service call."""

    def __init__(self, sync_service: ThreatActorMatchSyncService) -> None:
        self._sync = sync_service

    async def on_threat_actor_asset_class_targeting_updated(
        self,
        *,
        tenant_id: TenantId,
        event_id: str,
        threat_actor_ref: str,
        targeted_cve_ids: list[str],
        targeted_asset_classes: list[str],
        targeted_techniques: list[str] | None = None,
        targeted_iocs: list[str] | None = None,
        targeting_confidence: str = "Medium",
    ) -> int:
        return await self._sync.apply_targeting_event(
            tenant_id=tenant_id,
            event_id=event_id,
            threat_actor_ref=threat_actor_ref,
            targeted_cve_ids=targeted_cve_ids,
            targeted_asset_classes=targeted_asset_classes,
            targeted_techniques=targeted_techniques,
            targeted_iocs=targeted_iocs,
            confidence=targeting_confidence,
        )

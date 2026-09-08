"""CampaignFactory — the single supported construction path for
`Campaign` aggregates.

Stays pure/sync: it performs no I/O and calls no port. Scope-level
uniqueness of `canonical_name` must already have been checked by the
application service (repository existence check) BEFORE this factory is
invoked — mirroring `malware_intel`'s exact factory-stays-pure
discipline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign_intel.domain.aggregates.campaign import Campaign
from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignMotivation,
    CampaignStatus,
)
from campaign_intel.domain.value_objects.identifiers import CampaignId

if TYPE_CHECKING:
    from datetime import datetime

    from campaign_intel.domain.value_objects.enums import CampaignTargetSector
    from campaign_intel.domain.value_objects.identifiers import TenantId
    from campaign_intel.domain.value_objects.taxonomy import (
        CampaignAlias,
        CampaignObjective,
    )
    from campaign_intel.domain.value_objects.timeline import CampaignTimeline


class CampaignFactory:
    def observe(
        self,
        tenant_id: TenantId | None,
        canonical_name: str,
        now: datetime,
        status: CampaignStatus = CampaignStatus.UNKNOWN,
        motivation: CampaignMotivation = CampaignMotivation.UNKNOWN,
        timeline: CampaignTimeline | None = None,
        aliases: tuple[CampaignAlias, ...] = (),
        objectives: tuple[CampaignObjective, ...] = (),
        regions: tuple[str, ...] = (),
        target_sectors: tuple[CampaignTargetSector, ...] = (),
        confidence: CampaignConfidence = CampaignConfidence.MEDIUM,
    ) -> Campaign:
        return Campaign.observe(
            campaign_id=CampaignId.generate(),
            tenant_id=tenant_id,
            canonical_name=canonical_name,
            now=now,
            status=status,
            motivation=motivation,
            timeline=timeline,
            aliases=aliases,
            objectives=objectives,
            regions=regions,
            target_sectors=target_sectors,
            confidence=confidence,
        )

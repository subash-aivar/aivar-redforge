from __future__ import annotations

import random
from datetime import UTC, datetime

from campaign_intel.domain.aggregates.campaign import Campaign
from campaign_intel.domain.value_objects.enums import CampaignConfidence
from campaign_intel.domain.value_objects.evidence import SourceAttribution
from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def random_name(prefix: str = "campaign") -> str:
    """Already in normalized form (lowercase, no separator runs) so a
    raw-string repository lookup matches what the aggregate stores —
    normalization would otherwise collapse `-`/`_` to a space."""
    return f"{prefix}{random.randint(1, 10**12)}"


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{random.randint(1, 10**9)}",
        observed_at=datetime(2026, 8, 5, tzinfo=UTC),
        confidence=CampaignConfidence.HIGH,
    )


def make_campaign(
    *,
    tenant_id: TenantId | None = None,
    canonical_name: str | None = None,
) -> Campaign:
    now = datetime(2026, 8, 5, tzinfo=UTC)
    return Campaign.observe(
        campaign_id=CampaignId.generate(),
        tenant_id=tenant_id,
        canonical_name=canonical_name or random_name(),
        now=now,
    )

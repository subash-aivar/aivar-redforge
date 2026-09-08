"""CampaignIdentityPolicy — no duplicate `canonical_name` within a scope
(`tenant_id`, or global when `tenant_id is None`). The domain-layer half
of the two-layer defense; see `CampaignApplicationService` for the
repository-existence-check half, mirroring `malware_intel`'s dedup
discipline exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign_intel.domain.exceptions.domain_exceptions import DuplicateCampaignError

if TYPE_CHECKING:
    from campaign_intel.domain.aggregates.campaign import Campaign


class CampaignIdentityPolicy:
    @staticmethod
    def assert_no_duplicate(existing: list[Campaign], canonical_name: str) -> None:
        for campaign in existing:
            if campaign.canonical_name == canonical_name:
                raise DuplicateCampaignError(canonical_name)

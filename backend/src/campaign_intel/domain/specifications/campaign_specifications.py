"""Predicate specifications over `Campaign`. Pure, in-memory predicates
only — no query building, no persistence concerns (mirrors
`malware_intel.domain.specifications.malware_specifications`).

Note the two independent axes: `Active*`/`DeprecatedOrRevoked*` read the
RECORD lifecycle; `Ongoing*` reads the REAL-WORLD campaign status."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from campaign_intel.domain.value_objects.enums import (
    CampaignLifecycleStatus,
    CampaignStatus,
)

if TYPE_CHECKING:
    from campaign_intel.domain.aggregates.campaign import Campaign


class CampaignSpecification(Protocol):
    def is_satisfied_by(self, campaign: Campaign) -> bool: ...


class IsGlobalCampaignSpecification:
    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.tenant_id is None


class IsTenantCampaignSpecification:
    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.tenant_id is not None


class ActiveCampaignSpecification:
    """RECORD-lifecycle predicate — says nothing about whether the
    real-world campaign is still running."""

    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.lifecycle_status is CampaignLifecycleStatus.ACTIVE


class DeprecatedOrRevokedCampaignSpecification:
    _TERMINAL = frozenset({CampaignLifecycleStatus.DEPRECATED, CampaignLifecycleStatus.REVOKED})

    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.lifecycle_status in self._TERMINAL


class SupersededCampaignSpecification:
    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.lifecycle_status is CampaignLifecycleStatus.SUPERSEDED


class OngoingCampaignSpecification:
    """REAL-WORLD status predicate — says nothing about whether the
    RedForge record is still active."""

    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.status is CampaignStatus.ONGOING


class ConcludedCampaignSpecification:
    def is_satisfied_by(self, campaign: Campaign) -> bool:
        return campaign.status is CampaignStatus.CONCLUDED

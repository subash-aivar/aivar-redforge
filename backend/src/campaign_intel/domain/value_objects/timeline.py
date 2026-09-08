"""CampaignTimeline — the observation window of a real-world adversary
campaign.

Distinct from the record's `created_at`/`updated_at` (when RedForge
learned things) and from `CampaignStatus` (the assessed operational
state): this is purely the observed activity window."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from campaign_intel.domain.exceptions.domain_exceptions import InvalidTimelineError

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class CampaignTimeline:
    first_observed: datetime
    last_observed: datetime | None = None
    ongoing: bool = False

    def __post_init__(self) -> None:
        if self.last_observed is not None and self.last_observed < self.first_observed:
            raise InvalidTimelineError("last_observed must not precede first_observed")
        if self.ongoing and self.last_observed is not None:
            # An "ongoing" window has no closing bound by definition.
            raise InvalidTimelineError("an ongoing timeline must not set last_observed")

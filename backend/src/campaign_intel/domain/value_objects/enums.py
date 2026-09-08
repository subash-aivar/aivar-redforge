"""Closed enums for campaign_intel.

Two enums here describe two INDEPENDENT axes and must never be
conflated:

- `CampaignStatus` — the real-world adversary campaign's own
  operational state (is the campaign still running out there?).
- `CampaignLifecycleStatus` — RedForge's OWN record lifecycle (is this
  intelligence RECORD still the one to trust?).

A CONCLUDED campaign can have a perfectly ACTIVE record; a REVOKED
record can describe a campaign that is still ONGOING.
"""

from __future__ import annotations

from enum import StrEnum, unique

__all__ = [
    "CampaignConfidence",
    "CampaignLifecycleStatus",
    "CampaignMotivation",
    "CampaignObjectiveType",
    "CampaignStatus",
    "CampaignTargetSector",
]


@unique
class CampaignLifecycleStatus(StrEnum):
    """RedForge-native RECORD lifecycle for a `Campaign` intel record.
    See `LifecycleTransitionPolicy` for the enforced transition table."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


@unique
class CampaignStatus(StrEnum):
    """The real-world adversary campaign's own operational state. See
    `StatusTransitionPolicy` for the enforced transition table."""

    UNKNOWN = "unknown"
    ONGOING = "ongoing"
    SUSPECTED_CONCLUDED = "suspected_concluded"
    CONCLUDED = "concluded"


@unique
class CampaignMotivation(StrEnum):
    """The adversary's overarching motivation for running the
    campaign."""

    FINANCIAL = "financial"
    ESPIONAGE = "espionage"
    IDEOLOGICAL = "ideological"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


@unique
class CampaignObjectiveType(StrEnum):
    """RedForge's own curated, closed objective vocabulary."""

    ESPIONAGE = "espionage"
    FINANCIAL_GAIN = "financial_gain"
    DISRUPTION = "disruption"
    DESTRUCTION = "destruction"
    HACKTIVISM = "hacktivism"
    ACCESS_BROKERING = "access_brokering"
    OTHER = "other"


@unique
class CampaignTargetSector(StrEnum):
    """RedForge's own curated, closed target-sector vocabulary.

    Sectors are cleanly closed; geography deliberately is NOT — regions
    are format-validated free strings, not an enum (see
    `campaign_intel.domain.value_objects.taxonomy.normalize_region`)."""

    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    ENERGY = "energy"
    TECHNOLOGY = "technology"
    DEFENSE = "defense"
    EDUCATION = "education"
    RETAIL = "retail"
    TELECOMMUNICATIONS = "telecommunications"
    MANUFACTURING = "manufacturing"
    OTHER = "other"


@unique
class CampaignConfidence(StrEnum):
    """Analyst confidence in a campaign claim or attribution."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

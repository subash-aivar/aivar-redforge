"""Campaign taxonomy value objects — alias, objective, region (M51.5
Phase D2). All are RedForge-native and defined locally: no cross-import
of another bounded context's domain module."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from campaign_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidRegionError,
)

if TYPE_CHECKING:
    from campaign_intel.domain.value_objects.enums import CampaignObjectiveType

_REGION_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,31}$")


def normalize_region(raw: str) -> str:
    """Normalize a targeted region/country code.

    Geography is deliberately NOT a closed enum — the world's regions do
    not close cleanly and every intel feed slices them differently. What
    IS enforced is a deterministic, comparable FORMAT: NFKC-free ASCII
    upper-case letters/digits/hyphens, trimmed, non-empty (e.g. "EU",
    "US", "APAC", "SE-ASIA").
    """
    if not isinstance(raw, str):
        raise InvalidRegionError(str(raw))
    normalized = raw.strip().upper().replace("_", "-")
    normalized = re.sub(r"\s+", "-", normalized).strip("-")
    if not normalized or not _REGION_PATTERN.match(normalized):
        raise InvalidRegionError(raw)
    return normalized


@dataclass(frozen=True, slots=True)
class CampaignAlias:
    """An alternate name this campaign is tracked under by another
    vendor or feed. Never an identity — identity is `canonical_name`."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("alias value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CampaignObjective:
    """A stated/assessed objective of the campaign: a closed
    `objective_type` plus a free-text analyst description."""

    objective_type: CampaignObjectiveType
    description: str = ""

    def __str__(self) -> str:
        return self.objective_type.value

"""Evidence value objects for campaign_intel.

Mirrors `malware_intel.domain.value_objects.evidence`'s shape/spirit but
is defined locally — no cross-import of another bounded context's domain
module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from campaign_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError
from campaign_intel.domain.value_objects.enums import CampaignConfidence

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """A free-form citation backing a claim about this campaign — a
    vendor report URL, an incident reference, an analyst note."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("evidence citation value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """Structured evidence backing a claim (observation, alias,
    objective, region, sector, status or lifecycle transition) made by
    this bounded context."""

    source_system: str
    reference: str
    observed_at: datetime
    confidence: CampaignConfidence = CampaignConfidence.MEDIUM
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.source_system.strip():
            raise EmptyIdentifierError("source_system")
        if not self.reference.strip():
            raise EmptyIdentifierError("reference")

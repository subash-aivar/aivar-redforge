"""Evidence value objects for infrastructure_intel.

Mirrors `tool_intel.domain.value_objects.evidence`'s shape/spirit but is
defined locally — no cross-import of another bounded context's domain
module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from infrastructure_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError
from infrastructure_intel.domain.value_objects.enums import InfrastructureConfidence

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """A free-form citation backing a claim about this infrastructure —
    a vendor report URL, a passive-DNS reference, an analyst note."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("evidence citation value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """Structured evidence backing a claim (observation, hosting
    provider, cloud tenancy, region, ownership or lifecycle transition)
    made by this bounded context."""

    source_system: str
    reference: str
    observed_at: datetime
    confidence: InfrastructureConfidence = InfrastructureConfidence.MEDIUM
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.source_system.strip():
            raise EmptyIdentifierError("source_system")
        if not self.reference.strip():
            raise EmptyIdentifierError("reference")

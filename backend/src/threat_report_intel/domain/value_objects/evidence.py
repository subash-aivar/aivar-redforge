"""Evidence value objects for threat_report_intel.

Mirrors `infrastructure_intel.domain.value_objects.evidence`'s
shape/spirit but is defined locally — no cross-import of another
bounded context's domain module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from threat_report_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError
from threat_report_intel.domain.value_objects.enums import ThreatReportConfidence

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """A free-form citation backing a claim RedForge makes ABOUT this
    report — a corroborating vendor write-up, an analyst note, a peer
    review reference."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("evidence citation value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """Structured evidence backing a claim (the observation itself, a
    reference, a citation, or a lifecycle transition) made by this
    bounded context."""

    source_system: str
    reference: str
    observed_at: datetime
    confidence: ThreatReportConfidence = ThreatReportConfidence.MEDIUM
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.source_system.strip():
            raise EmptyIdentifierError("source_system")
        if not self.reference.strip():
            raise EmptyIdentifierError("reference")

"""Evidence value objects for intelligence_relationships (M51.4 Phase
C1).

`SourceAttribution` and `EvidenceCitation` mirror the shape/spirit of
`ioc_intelligence`'s provenance VOs but are defined locally — no
cross-import of another bounded context's domain module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from intelligence_relationships.domain.exceptions.domain_exceptions import EmptyIdentifierError
from intelligence_relationships.domain.value_objects.enums import RelationshipConfidence

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """A free-form citation backing a relationship claim (a report URL,
    a case reference, an analyst note id). Deliberately minimal — the
    structured, per-source judgment lives on `SourceAttribution`."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """Evidence backing a claim (creation, citation, epistemic
    transition, or lifecycle transition) made by this bounded context.
    Every mutation that asserts a RedForge-native fact requires one."""

    source_system: str
    reference: str
    observed_at: datetime
    confidence: RelationshipConfidence = RelationshipConfidence.MEDIUM
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.source_system.strip():
            raise EmptyIdentifierError("source_system")
        if not self.reference.strip():
            raise EmptyIdentifierError("reference")

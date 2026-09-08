"""SourceAttribution — evidence VO for attack_pattern_intel (M51.3
Phase B1).

Mirrors `ioc_intelligence.domain.value_objects.provenance.
SourceAttribution`'s shape/spirit (source system, external id,
observed time, confidence) but is defined locally — no cross-import of
another bounded context's domain module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from attack_pattern_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """Evidence backing a claim (creation, guidance, mitigation,
    procedure example, relationship, or lifecycle transition) made by
    this bounded context. Every `AttackPattern` mutation that asserts a
    RedForge-native fact requires one of these."""

    source_system: str
    reference: str
    observed_at: datetime
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.source_system.strip():
            raise EmptyIdentifierError("source_system")
        if not self.reference.strip():
            raise EmptyIdentifierError("reference")

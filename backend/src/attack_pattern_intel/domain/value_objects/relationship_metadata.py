"""RelationshipMetadata — native relationship between two AttackPattern
aggregates, distinct from legacy STIX `attack_technique_relationships`
(which relate raw MITRE techniques, not RedForge-native records)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from attack_pattern_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
    from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId


@dataclass(frozen=True, slots=True)
class RelationshipMetadata:
    relationship_type: str
    target_attack_pattern_id: AttackPatternId
    attribution: SourceAttribution

    def __post_init__(self) -> None:
        if not self.relationship_type.strip():
            raise EmptyIdentifierError("relationship_type")

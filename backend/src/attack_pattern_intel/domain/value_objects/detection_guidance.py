"""DetectionGuidance — RedForge-native guidance content, evidence-cited."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from attack_pattern_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution


@dataclass(frozen=True, slots=True)
class DetectionGuidance:
    content: str
    attribution: SourceAttribution

    def __post_init__(self) -> None:
        if not self.content.strip():
            raise EmptyIdentifierError("content")

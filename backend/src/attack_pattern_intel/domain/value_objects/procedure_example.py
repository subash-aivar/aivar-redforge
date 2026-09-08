"""ProcedureExample — RedForge-native procedure record, evidence-cited.
`actor_ref` is an opaque string (e.g. a threat-actor or campaign name)
never a foreign-key import of another bounded context's identity
type."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from attack_pattern_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution


@dataclass(frozen=True, slots=True)
class ProcedureExample:
    description: str
    attribution: SourceAttribution
    actor_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.description.strip():
            raise EmptyIdentifierError("description")

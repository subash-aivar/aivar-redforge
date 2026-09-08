"""TacticMapping — RedForge-curated mapping to a legacy tactic
(referenced by opaque id/shortname only; no tactic catalog owned
here)."""

from __future__ import annotations

from dataclasses import dataclass

from attack_pattern_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError


@dataclass(frozen=True, slots=True)
class TacticMapping:
    tactic_id: str
    tactic_shortname: str
    priority: int = 0
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.tactic_id.strip():
            raise EmptyIdentifierError("tactic_id")
        if not self.tactic_shortname.strip():
            raise EmptyIdentifierError("tactic_shortname")

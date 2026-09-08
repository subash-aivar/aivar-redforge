"""Evidence-citation value object for ioc_intelligence (M51.2 Phase A).

Mirrors `threat_actor_intel.domain.value_objects.evidence.
EvidenceCitation`'s exact shape (required, non-empty pointer) — own
type per this context, not imported, matching the opaque-per-context
VO discipline `threat_actor_intel` already established. Whether the
citation actually resolves to a real internal evidence record is a
future application-layer concern (an `IEvidenceValidationPort`-style
ACL adapter, per the precedent already proven in `threat_actor_intel`
Phase 3/4.5) — out of scope for this domain-only phase."""

from __future__ import annotations

from dataclasses import dataclass

from ioc_intelligence.domain.exceptions.domain_exceptions import EmptyIdentifierError


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("EvidenceCitation")

    def __str__(self) -> str:
        return self.value

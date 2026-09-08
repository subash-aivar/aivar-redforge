"""Evidence-citation value object for threat_actor_intel (M51.1).

`EvidenceCitation` is a required, non-empty pointer a
`ThreatActorAssociation` must carry — the concrete expression of
ADR-M51.1-08's evidence-trust model. This VO only enforces the
intrinsic rule that a citation string is non-empty; whether the
citation actually resolves to a real evidence record or a named
external source is validated by a future `IEvidenceValidationPort`
ACL adapter at the application layer (Phase 2), not here.
"""

from __future__ import annotations

from dataclasses import dataclass

from threat_actor_intel.domain.exceptions.domain_exceptions import EmptyEvidenceCitationError


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyEvidenceCitationError()

    def __str__(self) -> str:
        return self.value

"""AttributionConfidencePolicy — derives a `ThreatActor`'s
`AttributionConfidence` from the volume of corroborating evidence
associated with it (M51A).

A pure function of already-known aggregate state — never set
directly by a caller (see `ThreatActor`'s docstring on
`attribution_confidence`). Recomputed by the aggregate itself after
every mutation that changes the evidence it depends on (technique/
indicator association, sophistication update).

Rule (deliberately conservative — evidence-count-driven, not a
guess): `HIGH` requires both substantial technique corroboration
(3+ associated techniques) and a capability tier consistent with
sustained, deliberate operations (`EXPERT`/`INNOVATOR`); `MEDIUM`
requires at least one piece of corroborating evidence (a technique
or indicator association) at any sophistication; otherwise `LOW`.
"""

from __future__ import annotations

from threat_actor_intel.domain.value_objects.enums import AttributionConfidence, SophisticationLevel

_HIGH_CONFIDENCE_SOPHISTICATION = frozenset(
    {SophisticationLevel.EXPERT, SophisticationLevel.INNOVATOR}
)
_HIGH_CONFIDENCE_MIN_TECHNIQUES = 3


class AttributionConfidencePolicy:
    @staticmethod
    def derive(
        *,
        technique_count: int,
        indicator_count: int,
        sophistication: SophisticationLevel,
    ) -> AttributionConfidence:
        if (
            technique_count >= _HIGH_CONFIDENCE_MIN_TECHNIQUES
            and sophistication in _HIGH_CONFIDENCE_SOPHISTICATION
        ):
            return AttributionConfidence.HIGH
        if technique_count >= 1 or indicator_count >= 1:
            return AttributionConfidence.MEDIUM
        return AttributionConfidence.LOW

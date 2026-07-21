from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ai_agent_governance.domain.value_objects.enums import ReviewState

if TYPE_CHECKING:
    from ai_agent_governance.domain.aggregates.agent_deviation_event import (
        AgentDeviationEvent,
    )
    from ai_agent_governance.domain.value_objects.identifiers import (
        AgentOperationalEnvelopeId,
    )


@dataclass(frozen=True, slots=True)
class EnvelopeRevisionAdvisory:
    envelope_id: str
    deviation_type: str
    confirmed_benign_count: int
    recommendation: str


class EnvelopeRevisionAdvisoryService:
    """Surfaces human-only revision recommendations — never auto-applies."""

    def __init__(self, *, threshold: int = 3) -> None:
        self._threshold = threshold

    def advise(
        self,
        envelope_id: AgentOperationalEnvelopeId,
        deviations: list[AgentDeviationEvent],
    ) -> list[EnvelopeRevisionAdvisory]:
        counts: dict[str, int] = {}
        for d in deviations:
            if d.review_state != ReviewState.CONFIRMED_BENIGN:
                continue
            if str(d.envelope_ref.envelope_id) != str(envelope_id):
                continue
            key = d.deviation_type.value
            counts[key] = counts.get(key, 0) + 1
        advisories: list[EnvelopeRevisionAdvisory] = []
        for dtype, count in counts.items():
            if count >= self._threshold:
                advisories.append(
                    EnvelopeRevisionAdvisory(
                        envelope_id=str(envelope_id),
                        deviation_type=dtype,
                        confirmed_benign_count=count,
                        recommendation=(
                            f"Consider revising envelope to authorize {dtype} "
                            f"after {count} confirmed-benign reviews (human decision only)."
                        ),
                    )
                )
        return advisories

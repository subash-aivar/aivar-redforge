from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_agent_governance.domain.events.governance_events import (
    AgentDeviationConfirmed,
    AgentDeviationDetected,
    AgentDeviationDismissedBenign,
    AgentDeviationReviewed,
)
from ai_agent_governance.domain.exceptions.domain_exceptions import (
    DeviationImmutable,
    EnvelopeRevisionLinkRequired,
    InvalidReviewTransition,
    ReviewNotesRequired,
    TenantMismatch,
)
from ai_agent_governance.domain.value_objects.enums import (
    DeviationSeverity,
    DeviationType,
    ReviewState,
)

if TYPE_CHECKING:
    from datetime import datetime

    from ai_agent_governance.domain.events.base import BaseDomainEvent
    from ai_agent_governance.domain.value_objects.governance_vos import (
        AgentOperationalEnvelopeRef,
        ObservedAction,
    )
    from ai_agent_governance.domain.value_objects.identifiers import (
        AgentDeviationEventId,
        AISystemAssetId,
        TenantId,
    )

_TERMINAL = frozenset(
    {
        ReviewState.CONFIRMED_DEVIATION,
        ReviewState.CONFIRMED_BENIGN,
        ReviewState.ENVELOPE_UPDATED,
    }
)

_ALLOWED_REVIEW: dict[ReviewState, frozenset[ReviewState]] = {
    ReviewState.UNREVIEWED: frozenset({ReviewState.UNDER_REVIEW}),
    ReviewState.UNDER_REVIEW: frozenset(
        {
            ReviewState.CONFIRMED_DEVIATION,
            ReviewState.CONFIRMED_BENIGN,
            ReviewState.ENVELOPE_UPDATED,
        }
    ),
    ReviewState.CONFIRMED_DEVIATION: frozenset(),
    ReviewState.CONFIRMED_BENIGN: frozenset(),
    ReviewState.ENVELOPE_UPDATED: frozenset(),
}


class AgentDeviationEvent:
    __slots__ = (
        "_pending_events",
        "ai_system_asset_id",
        "detected_at",
        "deviation_id",
        "deviation_type",
        "envelope_ref",
        "linked_revision_event_id",
        "observed_action",
        "review_notes",
        "review_state",
        "severity",
        "tenant_id",
    )

    def __init__(
        self,
        deviation_id: AgentDeviationEventId,
        tenant_id: TenantId,
        envelope_ref: AgentOperationalEnvelopeRef,
        ai_system_asset_id: AISystemAssetId,
        deviation_type: DeviationType,
        observed_action: ObservedAction,
        severity: DeviationSeverity,
        detected_at: datetime,
        review_state: ReviewState,
        review_notes: str,
        linked_revision_event_id: str | None,
    ) -> None:
        self.deviation_id = deviation_id
        self.tenant_id = tenant_id
        self.envelope_ref = envelope_ref
        self.ai_system_asset_id = ai_system_asset_id
        self.deviation_type = deviation_type
        self.observed_action = observed_action
        self.severity = severity
        self.detected_at = detected_at
        self.review_state = review_state
        self.review_notes = review_notes
        self.linked_revision_event_id = linked_revision_event_id
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def mutate_core(self) -> None:
        raise DeviationImmutable()

    @classmethod
    def detect(
        cls,
        deviation_id: AgentDeviationEventId,
        tenant_id: TenantId,
        envelope_ref: AgentOperationalEnvelopeRef,
        ai_system_asset_id: AISystemAssetId,
        deviation_type: DeviationType,
        observed_action: ObservedAction,
        severity: DeviationSeverity,
        now: datetime,
    ) -> AgentDeviationEvent:
        if deviation_type == DeviationType.REQUIRED_APPROVAL_BYPASSED and severity not in {
            DeviationSeverity.HIGH,
            DeviationSeverity.CRITICAL,
        }:
            severity = DeviationSeverity.HIGH
        event = cls(
            deviation_id=deviation_id,
            tenant_id=tenant_id,
            envelope_ref=envelope_ref,
            ai_system_asset_id=ai_system_asset_id,
            deviation_type=deviation_type,
            observed_action=observed_action,
            severity=severity,
            detected_at=now,
            review_state=ReviewState.UNREVIEWED,
            review_notes="",
            linked_revision_event_id=None,
        )
        event._pending_events.append(
            AgentDeviationDetected(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(deviation_id),
                aggregate_type="AgentDeviationEvent",
                deviation_type=deviation_type.value,
                severity=severity.value,
                envelope_version=envelope_ref.envelope_version,
            )
        )
        return event

    def begin_review(self, tenant_id: TenantId, now: datetime) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        if self.review_state not in _ALLOWED_REVIEW:
            raise InvalidReviewTransition(self.review_state.value, ReviewState.UNDER_REVIEW.value)
        if ReviewState.UNDER_REVIEW not in _ALLOWED_REVIEW[self.review_state]:
            raise InvalidReviewTransition(self.review_state.value, ReviewState.UNDER_REVIEW.value)
        self.review_state = ReviewState.UNDER_REVIEW
        self._pending_events.append(
            AgentDeviationReviewed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.deviation_id),
                aggregate_type="AgentDeviationEvent",
                review_state=self.review_state.value,
            )
        )

    def confirm_deviation(self, tenant_id: TenantId, notes: str, now: datetime) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        if ReviewState.CONFIRMED_DEVIATION not in _ALLOWED_REVIEW.get(
            self.review_state, frozenset()
        ):
            raise InvalidReviewTransition(
                self.review_state.value, ReviewState.CONFIRMED_DEVIATION.value
            )
        self.review_state = ReviewState.CONFIRMED_DEVIATION
        self.review_notes = notes
        self._pending_events.append(
            AgentDeviationConfirmed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.deviation_id),
                aggregate_type="AgentDeviationEvent",
            )
        )

    def dismiss_benign(self, tenant_id: TenantId, notes: str, now: datetime) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        if not notes.strip():
            raise ReviewNotesRequired()
        if ReviewState.CONFIRMED_BENIGN not in _ALLOWED_REVIEW.get(self.review_state, frozenset()):
            raise InvalidReviewTransition(
                self.review_state.value, ReviewState.CONFIRMED_BENIGN.value
            )
        self.review_state = ReviewState.CONFIRMED_BENIGN
        self.review_notes = notes.strip()
        self._pending_events.append(
            AgentDeviationDismissedBenign(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.deviation_id),
                aggregate_type="AgentDeviationEvent",
                notes=self.review_notes,
            )
        )

    def close_as_envelope_updated(
        self,
        tenant_id: TenantId,
        linked_revision_event_id: str,
        now: datetime,
    ) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        if not linked_revision_event_id.strip():
            raise EnvelopeRevisionLinkRequired()
        if ReviewState.ENVELOPE_UPDATED not in _ALLOWED_REVIEW.get(self.review_state, frozenset()):
            raise InvalidReviewTransition(
                self.review_state.value, ReviewState.ENVELOPE_UPDATED.value
            )
        self.review_state = ReviewState.ENVELOPE_UPDATED
        self.linked_revision_event_id = linked_revision_event_id
        self._pending_events.append(
            AgentDeviationReviewed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.deviation_id),
                aggregate_type="AgentDeviationEvent",
                review_state=self.review_state.value,
            )
        )

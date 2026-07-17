"""M24 Phase 3 — Evidence Recommendation aggregates.

EvidenceRecommendation — single human-reviewable suggestion
RecommendationBatch — generation run with idempotent fingerprint

Never certifies compliance. Never creates ConfirmedEvidenceLink
without an explicit accept → link transition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.compliance.events import (
    RecommendationAccepted,
    RecommendationConfidenceChanged,
    RecommendationGenerated,
    RecommendationLinked,
    RecommendationRejected,
)
from redforge.domain.compliance.exceptions import (
    DuplicateRecommendationError,
    InvalidRecommendationTransitionError,
    RecommendationInvariantError,
    RecommendationNotLinkableError,
)
from redforge.domain.compliance.recommendation_value_objects import (
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
    RecommendationConfidence,
    RecommendationDecision,
    RecommendationStatus,
)
from redforge.shared.identifiers import EntityId

_LINKABLE_KINDS = frozenset(
    {
        EvidenceSourceKind.VALIDATION_EVIDENCE,
        EvidenceSourceKind.CONFIRMED_CONTROL_EVIDENCE,
    }
)

_ALLOWED_TRANSITIONS: dict[RecommendationStatus, frozenset[RecommendationStatus]] = {
    RecommendationStatus.RECOMMENDED: frozenset(
        {RecommendationStatus.ACCEPTED, RecommendationStatus.REJECTED}
    ),
    RecommendationStatus.ACCEPTED: frozenset(
        {RecommendationStatus.LINKED, RecommendationStatus.REJECTED}
    ),
    RecommendationStatus.LINKED: frozenset(),
    RecommendationStatus.REJECTED: frozenset(),
}


def recommendation_dedup_key(
    *,
    assessment_id: EntityId,
    reference: EvidenceReference,
) -> str:
    """Stable idempotency key: one active suggestion per assessment+evidence ref."""
    return f"{assessment_id}:{reference.dedup_token()}"


# ─── EvidenceRecommendation ───────────────────────────────────────────────────


@dataclass
class EvidenceRecommendation:
    """Aggregate root for a single evidence recommendation.

    Invariants:
      - Does not mutate ControlAssessment status
      - Does not create certifications
      - Link requires prior explicit acceptance
      - Only validation / confirmed-control evidence refs are linkable
    """

    id: EntityId
    organization_id: str
    batch_id: EntityId
    assessment_id: EntityId
    period_id: EntityId
    requirement_id: EntityId
    framework_key: str
    primary_reference: EvidenceReference
    candidates: tuple[EvidenceCandidate, ...]
    confidence: RecommendationConfidence
    score: float
    rationale: str
    status: RecommendationStatus
    dedup_key: str
    decision: RecommendationDecision | None
    linked_evidence_id: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime
    _pending_events: list[object] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self.organization_id.strip():
            raise RecommendationInvariantError("organization_id is required")
        if not (0.0 <= self.score <= 1.0):
            raise RecommendationInvariantError(
                f"score must be in [0,1], got {self.score}"
            )
        if len(self.rationale) > 4000:
            raise RecommendationInvariantError("rationale exceeds 4000 characters")
        if not self.dedup_key.strip():
            raise RecommendationInvariantError("dedup_key is required")
        if not self.candidates:
            raise RecommendationInvariantError(
                "EvidenceRecommendation requires at least one candidate"
            )

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        batch_id: EntityId,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        primary_reference: EvidenceReference,
        candidates: tuple[EvidenceCandidate, ...],
        confidence: RecommendationConfidence,
        score: float,
        rationale: str,
        created_by: str,
        recommendation_id: EntityId | None = None,
        now: datetime | None = None,
    ) -> EvidenceRecommendation:
        ts = now or datetime.now(UTC)
        rid = recommendation_id or EntityId.generate()
        dedup = recommendation_dedup_key(
            assessment_id=assessment_id, reference=primary_reference
        )
        rec = cls(
            id=rid,
            organization_id=organization_id,
            batch_id=batch_id,
            assessment_id=assessment_id,
            period_id=period_id,
            requirement_id=requirement_id,
            framework_key=framework_key,
            primary_reference=primary_reference,
            candidates=candidates,
            confidence=confidence,
            score=score,
            rationale=rationale,
            status=RecommendationStatus.RECOMMENDED,
            dedup_key=dedup,
            decision=None,
            linked_evidence_id=None,
            created_by=created_by,
            created_at=ts,
            updated_at=ts,
        )
        rec._pending_events.append(
            RecommendationGenerated(
                recommendation_id=str(rid),
                organization_id=organization_id,
                batch_id=str(batch_id),
                assessment_id=str(assessment_id),
                period_id=str(period_id),
                requirement_id=str(requirement_id),
                source_kind=primary_reference.source_kind.value,
                source_entity_id=primary_reference.source_entity_id,
                confidence=confidence.value,
                score=score,
                generated_by=created_by,
                occurred_at=ts,
            )
        )
        return rec

    def collect_events(self) -> list[object]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _assert_transition(self, target: RecommendationStatus) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.status, frozenset())
        if target not in allowed:
            raise InvalidRecommendationTransitionError(
                self.status.value, target.value
            )

    def update_confidence(
        self,
        *,
        confidence: RecommendationConfidence,
        score: float,
        rationale: str,
        changed_by: str,
        now: datetime | None = None,
    ) -> bool:
        """Update confidence while recommended. Returns True if values changed."""
        if self.status is not RecommendationStatus.RECOMMENDED:
            raise InvalidRecommendationTransitionError(
                self.status.value,
                "confidence_update",
                reason="confidence may only change while status is recommended",
            )
        if not (0.0 <= score <= 1.0):
            raise RecommendationInvariantError(f"score must be in [0,1], got {score}")
        previous = self.confidence.value
        if previous == confidence.value and abs(self.score - score) < 1e-9:
            return False
        ts = now or datetime.now(UTC)
        self.confidence = confidence
        self.score = score
        if rationale.strip():
            self.rationale = rationale
        self.updated_at = ts
        self._pending_events.append(
            RecommendationConfidenceChanged(
                recommendation_id=str(self.id),
                organization_id=self.organization_id,
                previous_confidence=previous,
                new_confidence=confidence.value,
                score=score,
                changed_by=changed_by,
                occurred_at=ts,
            )
        )
        return True

    def accept(
        self,
        *,
        accepted_by: str,
        rationale: str = "",
        now: datetime | None = None,
    ) -> None:
        self._assert_transition(RecommendationStatus.ACCEPTED)
        ts = now or datetime.now(UTC)
        self.status = RecommendationStatus.ACCEPTED
        self.decision = RecommendationDecision(
            decided_by=accepted_by,
            decided_at=ts,
            rationale=rationale,
        )
        self.updated_at = ts
        self._pending_events.append(
            RecommendationAccepted(
                recommendation_id=str(self.id),
                organization_id=self.organization_id,
                assessment_id=str(self.assessment_id),
                accepted_by=accepted_by,
                occurred_at=ts,
            )
        )

    def reject(
        self,
        *,
        rejected_by: str,
        rationale: str = "",
        now: datetime | None = None,
    ) -> None:
        self._assert_transition(RecommendationStatus.REJECTED)
        ts = now or datetime.now(UTC)
        self.status = RecommendationStatus.REJECTED
        self.decision = RecommendationDecision(
            decided_by=rejected_by,
            decided_at=ts,
            rationale=rationale,
        )
        self.updated_at = ts
        self._pending_events.append(
            RecommendationRejected(
                recommendation_id=str(self.id),
                organization_id=self.organization_id,
                assessment_id=str(self.assessment_id),
                rejected_by=rejected_by,
                rationale=rationale,
                occurred_at=ts,
            )
        )

    def linkable_evidence_id(self) -> str:
        """Evidence ID usable for ConfirmedEvidenceLink after accept."""
        if self.primary_reference.source_kind not in _LINKABLE_KINDS:
            raise RecommendationNotLinkableError(
                str(self.id),
                self.primary_reference.source_kind.value,
            )
        return self.primary_reference.source_entity_id

    def mark_linked(
        self,
        *,
        linked_by: str,
        evidence_id: str,
        now: datetime | None = None,
    ) -> None:
        """Record that a ConfirmedEvidenceLink was created after accept.

        Does not itself mutate ControlAssessment — application service
        performs confirm_evidence_link then calls this.
        """
        self._assert_transition(RecommendationStatus.LINKED)
        expected = self.linkable_evidence_id()
        if evidence_id != expected:
            raise RecommendationInvariantError(
                f"linked evidence_id '{evidence_id}' does not match "
                f"primary reference '{expected}'"
            )
        ts = now or datetime.now(UTC)
        self.status = RecommendationStatus.LINKED
        self.linked_evidence_id = evidence_id
        self.updated_at = ts
        self._pending_events.append(
            RecommendationLinked(
                recommendation_id=str(self.id),
                organization_id=self.organization_id,
                assessment_id=str(self.assessment_id),
                evidence_id=evidence_id,
                linked_by=linked_by,
                occurred_at=ts,
            )
        )


# ─── RecommendationBatch ──────────────────────────────────────────────────────


@dataclass
class RecommendationBatch:
    """Generation run aggregate — tracks idempotent recommendation production."""

    id: EntityId
    organization_id: str
    period_id: EntityId
    assessment_id: EntityId | None
    generation_fingerprint: str
    recommendation_ids: tuple[EntityId, ...]
    created_count: int
    updated_count: int
    skipped_duplicate_count: int
    generated_by: str
    created_at: datetime
    _pending_events: list[object] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self.organization_id.strip():
            raise RecommendationInvariantError("organization_id is required")
        if not self.generation_fingerprint.strip():
            raise RecommendationInvariantError("generation_fingerprint is required")
        if len(self.generation_fingerprint) > 128:
            raise RecommendationInvariantError(
                "generation_fingerprint exceeds 128 characters"
            )

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        period_id: EntityId,
        generation_fingerprint: str,
        generated_by: str,
        assessment_id: EntityId | None = None,
        batch_id: EntityId | None = None,
        now: datetime | None = None,
    ) -> RecommendationBatch:
        ts = now or datetime.now(UTC)
        return cls(
            id=batch_id or EntityId.generate(),
            organization_id=organization_id,
            period_id=period_id,
            assessment_id=assessment_id,
            generation_fingerprint=generation_fingerprint,
            recommendation_ids=(),
            created_count=0,
            updated_count=0,
            skipped_duplicate_count=0,
            generated_by=generated_by,
            created_at=ts,
        )

    def collect_events(self) -> list[object]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def record_results(
        self,
        *,
        recommendation_ids: tuple[EntityId, ...],
        created_count: int,
        updated_count: int,
        skipped_duplicate_count: int,
    ) -> None:
        self.recommendation_ids = recommendation_ids
        self.created_count = created_count
        self.updated_count = updated_count
        self.skipped_duplicate_count = skipped_duplicate_count


def assert_no_duplicate_active(
    *,
    dedup_key: str,
    existing: EvidenceRecommendation | None,
) -> None:
    """Raise if an active (non-rejected) recommendation already occupies the key."""
    if existing is None:
        return
    if existing.status is RecommendationStatus.REJECTED:
        return
    raise DuplicateRecommendationError(dedup_key, str(existing.id))

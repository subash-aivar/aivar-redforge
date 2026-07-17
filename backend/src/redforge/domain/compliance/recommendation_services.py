"""M24 Phase 3 — Evidence Recommendation domain services.

All scoring / ranking / policy / duplicate logic lives here — never in
controllers. AutoLinkingEngine recommends only; it never certifies and
never creates ConfirmedEvidenceLink without human accept → link.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from redforge.domain.compliance.recommendation import (
    EvidenceRecommendation,
    RecommendationBatch,
    recommendation_dedup_key,
)
from redforge.domain.compliance.recommendation_value_objects import (
    ConfidenceScoringWeights,
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
    RecommendationConfidence,
    RecommendationConfidenceCode,
    RecommendationPolicy,
    RecommendationStatus,
)
from redforge.shared.identifiers import EntityId  # noqa: TC001

# Baseline affinity by source kind (extensible - unknown kinds score low).
_SOURCE_BASE: dict[EvidenceSourceKind, float] = {
    EvidenceSourceKind.CONFIRMED_CONTROL_EVIDENCE: 0.95,
    EvidenceSourceKind.VALIDATION_EVIDENCE: 0.80,
    EvidenceSourceKind.INVESTIGATION_EVIDENCE: 0.55,
    EvidenceSourceKind.SECURITY_FINDING: 0.50,
    EvidenceSourceKind.CLOUD_SCAN: 0.45,
    EvidenceSourceKind.THREAT_INTELLIGENCE: 0.35,
}


@runtime_checkable
class EvidenceCandidateSource(Protocol):
    """Read-only port: produce candidates for a control assessment context."""

    async def find_candidates(
        self,
        *,
        organization_id: str,
        assessment_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: str,
        existing_confirmed_evidence_ids: frozenset[str],
    ) -> list[EvidenceCandidate]: ...


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate: EvidenceCandidate
    score: float
    confidence: RecommendationConfidence
    rationale: str


@dataclass(frozen=True, slots=True)
class AssessmentRecommendationContext:
    """Input context for generating recommendations (references only)."""

    organization_id: str
    assessment_id: EntityId
    period_id: EntityId
    requirement_id: EntityId
    framework_key: str
    existing_confirmed_evidence_ids: frozenset[str]
    mapping_confidence_hint: str | None = None


class ConfidenceScoringService:
    """Maps candidates to a normalized score and RecommendationConfidence."""

    def __init__(
        self,
        weights: ConfidenceScoringWeights | None = None,
    ) -> None:
        self._weights = weights or ConfidenceScoringWeights()

    def score(
        self,
        candidate: EvidenceCandidate,
        *,
        mapping_confidence_hint: str | None = None,
        recency_factor: float = 0.5,
    ) -> tuple[float, RecommendationConfidence]:
        if not (0.0 <= recency_factor <= 1.0):
            raise ValueError(f"recency_factor must be in [0,1], got {recency_factor}")

        source_base = _SOURCE_BASE.get(candidate.reference.source_kind, 0.25)
        source_component = source_base * self._weights.source_weight

        signal_density = min(1.0, len(candidate.signals) / 4.0)
        signal_component = signal_density * self._weights.signal_bonus

        hint_boost = 0.0
        if mapping_confidence_hint:
            hint = mapping_confidence_hint.strip().lower()
            if hint in {"exact", "high", "very_high"}:
                hint_boost = 1.0
            elif hint in {"partial", "medium"}:
                hint_boost = 0.6
            elif hint in {"related", "low"}:
                hint_boost = 0.3
        mapping_component = hint_boost * self._weights.mapping_hint_boost

        recency_component = recency_factor * self._weights.recency_boost

        # Blend with the candidate's own raw_score as an additional signal.
        blended = (
            0.55 * candidate.raw_score
            + 0.45
            * (
                source_component
                + signal_component
                + mapping_component
                + recency_component
            )
            / max(
                self._weights.source_weight
                + self._weights.signal_bonus
                + self._weights.mapping_hint_boost
                + self._weights.recency_boost,
                1e-9,
            )
        )
        score = max(0.0, min(1.0, blended))
        return score, RecommendationConfidence.from_score(score)


class RecommendationRankingService:
    """Orders scored candidates: confidence desc, score desc, stable ref token."""

    def rank(self, ranked: list[RankedCandidate]) -> list[RankedCandidate]:
        return sorted(
            ranked,
            key=lambda r: (
                -r.confidence.rank_index(),
                -r.score,
                r.candidate.reference.dedup_token(),
            ),
        )


class RecommendationPolicyEvaluator:
    """Gates which scored candidates become recommendations."""

    def __init__(self, policy: RecommendationPolicy | None = None) -> None:
        self._policy = policy or RecommendationPolicy()

    @property
    def policy(self) -> RecommendationPolicy:
        return self._policy

    def allows(self, confidence: RecommendationConfidence) -> bool:
        min_idx = self._policy.minimum_confidence_to_recommend.rank_index()
        if min_idx < 0:
            # Unknown minimum — treat as LOW
            min_idx = RecommendationConfidenceCode.ORDER.index(
                RecommendationConfidenceCode.LOW
            )
        return confidence.rank_index() >= min_idx

    def cap(self, ranked: list[RankedCandidate]) -> list[RankedCandidate]:
        return ranked[: self._policy.max_recommendations_per_assessment]


class DuplicateEvidenceResolver:
    """Merge equivalent candidates and detect duplicate recommendations."""

    def merge_candidates(
        self, candidates: list[EvidenceCandidate]
    ) -> list[EvidenceCandidate]:
        """Keep highest raw_score per EvidenceReference; merge signals."""
        best: dict[str, EvidenceCandidate] = {}
        for cand in candidates:
            token = cand.reference.dedup_token()
            existing = best.get(token)
            if existing is None:
                best[token] = cand
                continue
            if cand.raw_score > existing.raw_score:
                merged_signals = tuple(
                    dict.fromkeys([*existing.signals, *cand.signals])
                )
                best[token] = EvidenceCandidate(
                    reference=cand.reference,
                    raw_score=cand.raw_score,
                    rationale=cand.rationale or existing.rationale,
                    signals=merged_signals,
                )
            else:
                merged_signals = tuple(
                    dict.fromkeys([*existing.signals, *cand.signals])
                )
                best[token] = EvidenceCandidate(
                    reference=existing.reference,
                    raw_score=existing.raw_score,
                    rationale=existing.rationale,
                    signals=merged_signals,
                )
        return list(best.values())

    def is_already_confirmed(
        self,
        reference: EvidenceReference,
        confirmed_evidence_ids: frozenset[str],
    ) -> bool:
        if reference.source_kind in {
            EvidenceSourceKind.VALIDATION_EVIDENCE,
            EvidenceSourceKind.CONFIRMED_CONTROL_EVIDENCE,
        }:
            return reference.source_entity_id in confirmed_evidence_ids
        return False

    def find_active_duplicate(
        self,
        *,
        assessment_id: EntityId,
        reference: EvidenceReference,
        existing: list[EvidenceRecommendation],
    ) -> EvidenceRecommendation | None:
        key = recommendation_dedup_key(
            assessment_id=assessment_id, reference=reference
        )
        for rec in existing:
            if rec.dedup_key != key:
                continue
            if rec.status is RecommendationStatus.REJECTED:
                continue
            return rec
        return None


class EvidenceRecommendationService:
    """Domain factory: build EvidenceRecommendation from a RankedCandidate."""

    def build(
        self,
        *,
        organization_id: str,
        batch_id: EntityId,
        context: AssessmentRecommendationContext,
        ranked: RankedCandidate,
        created_by: str,
    ) -> EvidenceRecommendation:
        return EvidenceRecommendation.create(
            organization_id=organization_id,
            batch_id=batch_id,
            assessment_id=context.assessment_id,
            period_id=context.period_id,
            requirement_id=context.requirement_id,
            framework_key=context.framework_key,
            primary_reference=ranked.candidate.reference,
            candidates=(ranked.candidate,),
            confidence=ranked.confidence,
            score=ranked.score,
            rationale=ranked.rationale,
            created_by=created_by,
        )


@dataclass(frozen=True, slots=True)
class AutoLinkResult:
    """Outcome of AutoLinkingEngine for one assessment (recommendations only)."""

    created: tuple[EvidenceRecommendation, ...]
    updated: tuple[EvidenceRecommendation, ...]
    skipped_duplicate_count: int


class AutoLinkingEngine:
    """Enterprise recommendation engine.

    Name retained for Phase 3 foreshadowing: it *recommends* and prepares
    human-approved links — it NEVER auto-links, NEVER certifies, and NEVER
    changes ControlStatus.
    """

    def __init__(
        self,
        *,
        scoring: ConfidenceScoringService | None = None,
        ranking: RecommendationRankingService | None = None,
        policy: RecommendationPolicyEvaluator | None = None,
        duplicates: DuplicateEvidenceResolver | None = None,
        factory: EvidenceRecommendationService | None = None,
    ) -> None:
        self._scoring = scoring or ConfidenceScoringService()
        self._ranking = ranking or RecommendationRankingService()
        self._policy = policy or RecommendationPolicyEvaluator()
        self._duplicates = duplicates or DuplicateEvidenceResolver()
        self._factory = factory or EvidenceRecommendationService()

    def generation_fingerprint(
        self,
        *,
        organization_id: str,
        period_id: EntityId,
        assessment_id: EntityId | None,
        candidate_tokens: list[str],
    ) -> str:
        payload = "|".join(
            [
                organization_id,
                str(period_id),
                str(assessment_id) if assessment_id else "*",
                *sorted(candidate_tokens),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def recommend_for_assessment(
        self,
        *,
        batch: RecommendationBatch,
        context: AssessmentRecommendationContext,
        candidates: list[EvidenceCandidate],
        existing_recommendations: list[EvidenceRecommendation],
        created_by: str,
    ) -> AutoLinkResult:
        merged = self._duplicates.merge_candidates(candidates)
        ranked_list: list[RankedCandidate] = []
        for cand in merged:
            if self._duplicates.is_already_confirmed(
                cand.reference, context.existing_confirmed_evidence_ids
            ):
                continue
            score, confidence = self._scoring.score(
                cand,
                mapping_confidence_hint=context.mapping_confidence_hint,
            )
            if not self._policy.allows(confidence):
                continue
            rationale = (
                f"{cand.rationale} "
                f"[score={score:.3f} confidence={confidence.value}]"
            ).strip()
            ranked_list.append(
                RankedCandidate(
                    candidate=cand,
                    score=score,
                    confidence=confidence,
                    rationale=rationale,
                )
            )

        ordered = self._policy.cap(self._ranking.rank(ranked_list))
        created: list[EvidenceRecommendation] = []
        updated: list[EvidenceRecommendation] = []
        skipped = 0

        for ranked in ordered:
            dup = self._duplicates.find_active_duplicate(
                assessment_id=context.assessment_id,
                reference=ranked.candidate.reference,
                existing=existing_recommendations,
            )
            if dup is not None:
                if dup.status is RecommendationStatus.RECOMMENDED:
                    changed = dup.update_confidence(
                        confidence=ranked.confidence,
                        score=ranked.score,
                        rationale=ranked.rationale,
                        changed_by=created_by,
                    )
                    if changed:
                        updated.append(dup)
                    else:
                        skipped += 1
                else:
                    # accepted / linked — do not recreate or mutate
                    skipped += 1
                continue

            rec = self._factory.build(
                organization_id=context.organization_id,
                batch_id=batch.id,
                context=context,
                ranked=ranked,
                created_by=created_by,
            )
            created.append(rec)
            existing_recommendations.append(rec)

        return AutoLinkResult(
            created=tuple(created),
            updated=tuple(updated),
            skipped_duplicate_count=skipped,
        )

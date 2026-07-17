"""Domain tests for M24 Phase 3 Evidence Recommendation engine."""

from __future__ import annotations

import pytest

from redforge.domain.compliance.events import (
    RecommendationAccepted,
    RecommendationConfidenceChanged,
    RecommendationGenerated,
    RecommendationLinked,
    RecommendationRejected,
)
from redforge.domain.compliance.exceptions import (
    InvalidRecommendationTransitionError,
    RecommendationNotLinkableError,
)
from redforge.domain.compliance.recommendation import (
    EvidenceRecommendation,
    RecommendationBatch,
    recommendation_dedup_key,
)
from redforge.domain.compliance.recommendation_services import (
    AssessmentRecommendationContext,
    AutoLinkingEngine,
    ConfidenceScoringService,
    DuplicateEvidenceResolver,
    EvidenceRecommendationService,
    RecommendationPolicyEvaluator,
    RecommendationRankingService,
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
from redforge.shared.identifiers import EntityId

_ORG = "01ORG00000000000000000001"
_ACTOR = "01USER000000000000000001"


def _ref(
    kind: EvidenceSourceKind = EvidenceSourceKind.VALIDATION_EVIDENCE,
    eid: str = "01EVIDENCE00000000000001",
) -> EvidenceReference:
    return EvidenceReference(source_kind=kind, source_entity_id=eid)


def _candidate(
    *,
    kind: EvidenceSourceKind = EvidenceSourceKind.VALIDATION_EVIDENCE,
    eid: str = "01EVIDENCE00000000000001",
    raw_score: float = 0.8,
) -> EvidenceCandidate:
    return EvidenceCandidate(
        reference=_ref(kind, eid),
        raw_score=raw_score,
        rationale="test candidate",
        signals=("unit",),
    )


def test_confidence_from_score_bands() -> None:
    assert (
        RecommendationConfidence.from_score(0.1).value
        == RecommendationConfidenceCode.VERY_LOW
    )
    assert (
        RecommendationConfidence.from_score(0.3).value
        == RecommendationConfidenceCode.LOW
    )
    assert (
        RecommendationConfidence.from_score(0.5).value
        == RecommendationConfidenceCode.MEDIUM
    )
    assert (
        RecommendationConfidence.from_score(0.7).value
        == RecommendationConfidenceCode.HIGH
    )
    assert (
        RecommendationConfidence.from_score(0.95).value
        == RecommendationConfidenceCode.VERY_HIGH
    )


def test_confidence_preserves_unknown_future_values() -> None:
    conf = RecommendationConfidence.parse("auditor_endorsed")
    assert conf.value == "auditor_endorsed"
    assert conf.is_known is False
    assert conf.rank_index() == -1


def test_policy_rejects_auto_accept() -> None:
    with pytest.raises(ValueError, match="allow_auto_accept"):
        RecommendationPolicy(allow_auto_accept=True)


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match=r"sum to 1\.0"):
        ConfidenceScoringWeights(source_weight=0.5, signal_bonus=0.5)


def test_lifecycle_recommended_accept_link() -> None:
    batch = RecommendationBatch.create(
        organization_id=_ORG,
        period_id=EntityId.generate(),
        generation_fingerprint="abc",
        generated_by=_ACTOR,
    )
    assessment_id = EntityId.generate()
    rec = EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=batch.id,
        assessment_id=assessment_id,
        period_id=batch.period_id,
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=_ref(),
        candidates=(_candidate(),),
        confidence=RecommendationConfidence.parse("high"),
        score=0.82,
        rationale="strong match",
        created_by=_ACTOR,
    )
    events = rec.collect_events()
    assert any(isinstance(e, RecommendationGenerated) for e in events)

    rec.accept(accepted_by=_ACTOR, rationale="looks good")
    assert rec.status is RecommendationStatus.ACCEPTED
    assert any(isinstance(e, RecommendationAccepted) for e in rec.collect_events())

    rec.mark_linked(linked_by=_ACTOR, evidence_id="01EVIDENCE00000000000001")
    assert rec.status is RecommendationStatus.LINKED
    assert any(isinstance(e, RecommendationLinked) for e in rec.collect_events())


def test_reject_from_recommended() -> None:
    batch_id = EntityId.generate()
    rec = EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=batch_id,
        assessment_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=_ref(),
        candidates=(_candidate(),),
        confidence=RecommendationConfidence.parse("medium"),
        score=0.5,
        rationale="maybe",
        created_by=_ACTOR,
    )
    rec.collect_events()
    rec.reject(rejected_by=_ACTOR, rationale="not relevant")
    assert rec.status is RecommendationStatus.REJECTED
    assert any(isinstance(e, RecommendationRejected) for e in rec.collect_events())


def test_invalid_skip_to_linked() -> None:
    rec = EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=EntityId.generate(),
        assessment_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=_ref(),
        candidates=(_candidate(),),
        confidence=RecommendationConfidence.parse("high"),
        score=0.8,
        rationale="x",
        created_by=_ACTOR,
    )
    with pytest.raises(InvalidRecommendationTransitionError):
        rec.mark_linked(linked_by=_ACTOR, evidence_id="01EVIDENCE00000000000001")


def test_finding_source_not_linkable() -> None:
    rec = EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=EntityId.generate(),
        assessment_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=_ref(EvidenceSourceKind.SECURITY_FINDING, "01FINDING000000000000001"),
        candidates=(
            _candidate(kind=EvidenceSourceKind.SECURITY_FINDING, eid="01FINDING000000000000001"),
        ),
        confidence=RecommendationConfidence.parse("medium"),
        score=0.5,
        rationale="finding",
        created_by=_ACTOR,
    )
    rec.accept(accepted_by=_ACTOR)
    with pytest.raises(RecommendationNotLinkableError):
        rec.linkable_evidence_id()


def test_duplicate_resolver_merges_equivalent() -> None:
    resolver = DuplicateEvidenceResolver()
    a = _candidate(raw_score=0.4, eid="01EVIDENCE00000000000001")
    b = EvidenceCandidate(
        reference=_ref(),
        raw_score=0.9,
        rationale="better",
        signals=("extra",),
    )
    merged = resolver.merge_candidates([a, b])
    assert len(merged) == 1
    assert merged[0].raw_score == 0.9
    assert "unit" in merged[0].signals
    assert "extra" in merged[0].signals


def test_auto_linking_engine_idempotent_and_updates_confidence() -> None:
    engine = AutoLinkingEngine()
    batch = RecommendationBatch.create(
        organization_id=_ORG,
        period_id=EntityId.generate(),
        generation_fingerprint="fp",
        generated_by=_ACTOR,
    )
    assessment_id = EntityId.generate()
    context = AssessmentRecommendationContext(
        organization_id=_ORG,
        assessment_id=assessment_id,
        period_id=batch.period_id,
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        existing_confirmed_evidence_ids=frozenset(),
        mapping_confidence_hint="high",
    )
    candidates = [
        _candidate(eid="01EVIDENCE00000000000001", raw_score=0.85),
        _candidate(eid="01EVIDENCE00000000000001", raw_score=0.5),
    ]
    first = engine.recommend_for_assessment(
        batch=batch,
        context=context,
        candidates=candidates,
        existing_recommendations=[],
        created_by=_ACTOR,
    )
    assert len(first.created) == 1
    existing = list(first.created)

    second = engine.recommend_for_assessment(
        batch=batch,
        context=context,
        candidates=[_candidate(eid="01EVIDENCE00000000000001", raw_score=0.99)],
        existing_recommendations=existing,
        created_by=_ACTOR,
    )
    assert len(second.created) == 0
    assert second.skipped_duplicate_count + len(second.updated) == 1


def test_policy_filters_low_confidence() -> None:
    policy = RecommendationPolicyEvaluator(
        RecommendationPolicy(
            minimum_confidence_to_recommend=RecommendationConfidence.parse("high")
        )
    )
    assert policy.allows(RecommendationConfidence.parse("high")) is True
    assert policy.allows(RecommendationConfidence.parse("low")) is False


def test_scoring_service_configurable_weights() -> None:
    scoring = ConfidenceScoringService(
        ConfidenceScoringWeights(
            source_weight=0.7,
            signal_bonus=0.1,
            mapping_hint_boost=0.1,
            recency_boost=0.1,
        )
    )
    score, conf = scoring.score(
        _candidate(kind=EvidenceSourceKind.CONFIRMED_CONTROL_EVIDENCE, raw_score=0.95),
        mapping_confidence_hint="exact",
        recency_factor=1.0,
    )
    assert 0.0 <= score <= 1.0
    assert conf.rank_index() >= RecommendationConfidence.parse("medium").rank_index()


def test_ranking_orders_by_confidence_then_score() -> None:
    ranking = RecommendationRankingService()
    factory = EvidenceRecommendationService()
    _ = factory
    from redforge.domain.compliance.recommendation_services import RankedCandidate

    low = RankedCandidate(
        candidate=_candidate(eid="01EVIDENCE0000000000000A", raw_score=0.9),
        score=0.9,
        confidence=RecommendationConfidence.parse("low"),
        rationale="low",
    )
    high = RankedCandidate(
        candidate=_candidate(eid="01EVIDENCE0000000000000B", raw_score=0.5),
        score=0.5,
        confidence=RecommendationConfidence.parse("high"),
        rationale="high",
    )
    ordered = ranking.rank([low, high])
    assert ordered[0].confidence.value == "high"


def test_skips_already_confirmed_evidence() -> None:
    engine = AutoLinkingEngine()
    batch = RecommendationBatch.create(
        organization_id=_ORG,
        period_id=EntityId.generate(),
        generation_fingerprint="fp2",
        generated_by=_ACTOR,
    )
    eid = "01EVIDENCE00000000000001"
    context = AssessmentRecommendationContext(
        organization_id=_ORG,
        assessment_id=EntityId.generate(),
        period_id=batch.period_id,
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        existing_confirmed_evidence_ids=frozenset({eid}),
    )
    result = engine.recommend_for_assessment(
        batch=batch,
        context=context,
        candidates=[_candidate(eid=eid, raw_score=0.99)],
        existing_recommendations=[],
        created_by=_ACTOR,
    )
    assert result.created == ()


def test_confidence_change_emits_event() -> None:
    rec = EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=EntityId.generate(),
        assessment_id=EntityId.generate(),
        period_id=EntityId.generate(),
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=_ref(),
        candidates=(_candidate(),),
        confidence=RecommendationConfidence.parse("low"),
        score=0.3,
        rationale="old",
        created_by=_ACTOR,
    )
    rec.collect_events()
    changed = rec.update_confidence(
        confidence=RecommendationConfidence.parse("high"),
        score=0.8,
        rationale="new",
        changed_by=_ACTOR,
    )
    assert changed is True
    events = rec.collect_events()
    assert any(isinstance(e, RecommendationConfidenceChanged) for e in events)


def test_dedup_key_stable() -> None:
    aid = EntityId.generate()
    key = recommendation_dedup_key(assessment_id=aid, reference=_ref())
    assert key == f"{aid}:validation_evidence:01EVIDENCE00000000000001"

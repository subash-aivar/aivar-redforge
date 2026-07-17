"""Application service tests for M24 Phase 3 Evidence Recommendations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from redforge.application.compliance.recommendation_dtos import (
    AcceptRecommendationCommand,
    GenerateRecommendationsCommand,
    LinkRecommendationCommand,
    RejectRecommendationCommand,
)
from redforge.application.compliance.recommendation_service import (
    EvidenceRecommendationApplicationService,
)
from redforge.domain.compliance.assessment import (
    AssessmentPeriod,
    ComplianceProfile,
    ControlAssessment,
)
from redforge.domain.compliance.exceptions import (
    InvalidRecommendationTransitionError,
    RecommendationNotAcceptedError,
    RecommendationNotLinkableError,
)
from redforge.domain.compliance.recommendation import (
    EvidenceRecommendation,
    RecommendationBatch,
)
from redforge.domain.compliance.recommendation_value_objects import (
    EvidenceCandidate,
    EvidenceReference,
    EvidenceSourceKind,
    RecommendationConfidence,
    RecommendationStatus,
)
from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.shared.identifiers import EntityId

_ORG = "01ORG00000000000000000001"
_ACTOR = "01USER000000000000000001"
_EVIDENCE = "01EVIDENCE00000000000001"


class _FakeSource:
    def __init__(self, candidates: list[EvidenceCandidate]) -> None:
        self._candidates = candidates

    async def find_candidates(self, **kwargs: Any) -> list[EvidenceCandidate]:
        _ = kwargs
        return list(self._candidates)


class _InMemoryRecRepo:
    def __init__(self) -> None:
        self.batches: dict[str, RecommendationBatch] = {}
        self.by_fp: dict[str, RecommendationBatch] = {}
        self.recs: dict[str, EvidenceRecommendation] = {}

    async def save_batch(self, batch: RecommendationBatch) -> None:
        self.batches[str(batch.id)] = batch
        self.by_fp[batch.generation_fingerprint] = batch

    async def get_batch(
        self, organization_id: str, batch_id: EntityId
    ) -> RecommendationBatch | None:
        b = self.batches.get(str(batch_id))
        if b is None or b.organization_id != organization_id:
            return None
        return b

    async def get_batch_by_fingerprint(
        self, organization_id: str, generation_fingerprint: str
    ) -> RecommendationBatch | None:
        b = self.by_fp.get(generation_fingerprint)
        if b is None or b.organization_id != organization_id:
            return None
        return b

    async def save_recommendation(self, recommendation: EvidenceRecommendation) -> None:
        self.recs[str(recommendation.id)] = recommendation

    async def get_recommendation(
        self, organization_id: str, recommendation_id: EntityId
    ) -> EvidenceRecommendation | None:
        r = self.recs.get(str(recommendation_id))
        if r is None or r.organization_id != organization_id:
            return None
        return r

    async def get_recommendation_for_update(
        self, organization_id: str, recommendation_id: EntityId
    ) -> EvidenceRecommendation | None:
        return await self.get_recommendation(organization_id, recommendation_id)

    async def get_by_dedup_key(
        self, organization_id: str, dedup_key: str
    ) -> EvidenceRecommendation | None:
        for r in self.recs.values():
            if (
                r.organization_id == organization_id
                and r.dedup_key == dedup_key
                and r.status is not RecommendationStatus.REJECTED
            ):
                return r
        return None

    async def list_recommendations(
        self,
        organization_id: str,
        *,
        period_id: EntityId | None = None,
        assessment_id: EntityId | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[EvidenceRecommendation], int]:
        items = [
            r
            for r in self.recs.values()
            if r.organization_id == organization_id
            and (period_id is None or r.period_id == period_id)
            and (assessment_id is None or r.assessment_id == assessment_id)
            and (status is None or r.status.value == status)
        ]
        return items[offset : offset + limit], len(items)

    async def list_history(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> tuple[list[EvidenceRecommendation], int]:
        items = [
            r
            for r in self.recs.values()
            if r.organization_id == organization_id
            and r.status
            in {
                RecommendationStatus.ACCEPTED,
                RecommendationStatus.REJECTED,
                RecommendationStatus.LINKED,
            }
        ]
        return items[offset : offset + limit], len(items)

    async def statistics(
        self, organization_id: str, *, period_id: EntityId | None = None
    ) -> dict[str, int]:
        counts = {s.value: 0 for s in RecommendationStatus}
        for r in self.recs.values():
            if r.organization_id != organization_id:
                continue
            if period_id is not None and r.period_id != period_id:
                continue
            counts[r.status.value] += 1
        counts["total"] = sum(counts[s.value] for s in RecommendationStatus)
        return counts


class _InMemoryAssessmentRepo:
    def __init__(
        self,
        *,
        period: AssessmentPeriod,
        assessment: ControlAssessment,
        profile: ComplianceProfile,
    ) -> None:
        self.period = period
        self.assessment = assessment
        self.profile = profile

    async def get_period(
        self, organization_id: str, period_id: EntityId
    ) -> AssessmentPeriod | None:
        if self.period.organization_id != organization_id:
            return None
        if self.period.id != period_id:
            return None
        return self.period

    async def get_assessment(
        self, organization_id: str, assessment_id: EntityId
    ) -> ControlAssessment | None:
        if self.assessment.organization_id != organization_id:
            return None
        if self.assessment.id != assessment_id:
            return None
        return self.assessment

    async def list_assessments(
        self, organization_id: str, *, period_id: EntityId
    ) -> list[ControlAssessment]:
        if (
            self.assessment.organization_id == organization_id
            and self.assessment.period_id == period_id
        ):
            return [self.assessment]
        return []


class _SessionCtx:
    def __init__(self, session: MagicMock) -> None:
        self._session = session

    async def __aenter__(self) -> MagicMock:
        return self._session

    async def __aexit__(self, *args: object) -> None:
        return None


class _BeginCtx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *args: object) -> None:
        return None


def _build_fixture() -> tuple[
    ComplianceProfile, AssessmentPeriod, ControlAssessment, _InMemoryRecRepo
]:
    profile = ComplianceProfile.create(
        organization_id=_ORG,
        name="Program",
        framework_keys=(FrameworkKey.SOC2,),
        created_by=_ACTOR,
    )
    profile.activate(activated_by=_ACTOR)
    start = datetime.now(UTC)
    period = AssessmentPeriod.create(
        organization_id=_ORG,
        profile_id=profile.id,
        name="Q1",
        framework_key=FrameworkKey.SOC2,
        period_start=start,
        period_end=start + timedelta(days=90),
        created_by=_ACTOR,
    )
    period.open(opened_by=_ACTOR)
    assessment = ControlAssessment.create(
        organization_id=_ORG,
        profile_id=profile.id,
        period_id=period.id,
        requirement_id=EntityId.generate(),
        framework_key=FrameworkKey.SOC2,
        created_by=_ACTOR,
    )
    return profile, period, assessment, _InMemoryRecRepo()


@pytest.fixture
def wired_service() -> tuple[
    EvidenceRecommendationApplicationService,
    AssessmentPeriod,
    ControlAssessment,
    _InMemoryRecRepo,
]:
    profile, period, assessment, rec_repo = _build_fixture()
    assess_repo = _InMemoryAssessmentRepo(
        period=period, assessment=assessment, profile=profile
    )
    catalog = MagicMock()
    catalog.list_mappings = AsyncMock(return_value=([], 0))

    session = MagicMock()
    session.begin = MagicMock(return_value=_BeginCtx())

    factory = MagicMock()
    factory.return_value = _SessionCtx(session)

    candidates = [
        EvidenceCandidate(
            reference=EvidenceReference(
                source_kind=EvidenceSourceKind.VALIDATION_EVIDENCE,
                source_entity_id=_EVIDENCE,
            ),
            raw_score=0.9,
            rationale="validation evidence",
            signals=("unit",),
        )
    ]

    svc = EvidenceRecommendationApplicationService(
        factory,
        candidate_source_factory=lambda _s: [_FakeSource(candidates)],
    )
    svc._recommendation_repo = lambda _s: rec_repo  # type: ignore[method-assign]
    svc._assessment_repo = lambda _s: assess_repo  # type: ignore[method-assign]
    svc._catalog_repo = lambda _s: catalog  # type: ignore[method-assign]
    return svc, period, assessment, rec_repo


@pytest.mark.asyncio
async def test_generate_creates_recommendations(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, rec_repo = wired_service
    batch = await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    assert batch.created_count == 1
    assert len(rec_repo.recs) == 1
    rec = next(iter(rec_repo.recs.values()))
    assert rec.status is RecommendationStatus.RECOMMENDED
    assert rec.assessment_id == assessment.id


@pytest.mark.asyncio
async def test_generate_idempotent_by_fingerprint(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, rec_repo = wired_service
    cmd = GenerateRecommendationsCommand(
        organization_id=_ORG,
        period_id=period.id,
        assessment_id=assessment.id,
        generated_by=_ACTOR,
    )
    first = await svc.generate(cmd)
    second = await svc.generate(cmd)
    assert first.id == second.id
    assert len(rec_repo.recs) == 1


@pytest.mark.asyncio
async def test_accept_reject_transitions(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, rec_repo = wired_service
    await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    rid = next(iter(rec_repo.recs.values())).id
    accepted = await svc.accept(
        AcceptRecommendationCommand(
            organization_id=_ORG,
            recommendation_id=rid,
            accepted_by=_ACTOR,
        )
    )
    assert accepted.status is RecommendationStatus.ACCEPTED

    with pytest.raises(InvalidRecommendationTransitionError):
        await svc.accept(
            AcceptRecommendationCommand(
                organization_id=_ORG,
                recommendation_id=rid,
                accepted_by=_ACTOR,
            )
        )


@pytest.mark.asyncio
async def test_reject_path(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, rec_repo = wired_service
    await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    rid = next(iter(rec_repo.recs.values())).id
    rejected = await svc.reject(
        RejectRecommendationCommand(
            organization_id=_ORG,
            recommendation_id=rid,
            rejected_by=_ACTOR,
            rationale="noise",
        )
    )
    assert rejected.status is RecommendationStatus.REJECTED


@pytest.mark.asyncio
async def test_link_requires_accept(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, rec_repo = wired_service
    await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    rid = next(iter(rec_repo.recs.values())).id
    with pytest.raises(RecommendationNotAcceptedError):
        await svc.link_accepted(
            LinkRecommendationCommand(
                organization_id=_ORG,
                recommendation_id=rid,
                linked_by=_ACTOR,
            )
        )


@pytest.mark.asyncio
async def test_link_accepted_calls_confirm_evidence(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, rec_repo = wired_service
    await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    rid = next(iter(rec_repo.recs.values())).id
    await svc.accept(
        AcceptRecommendationCommand(
            organization_id=_ORG,
            recommendation_id=rid,
            accepted_by=_ACTOR,
        )
    )
    assess_svc = MagicMock()
    assess_svc.confirm_evidence_link_in_session = AsyncMock(return_value=assessment)
    svc._assessment_service = assess_svc

    linked = await svc.link_accepted(
        LinkRecommendationCommand(
            organization_id=_ORG,
            recommendation_id=rid,
            linked_by=_ACTOR,
        )
    )
    assert linked.status is RecommendationStatus.LINKED
    assess_svc.confirm_evidence_link_in_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_statistics(
    wired_service: tuple[
        EvidenceRecommendationApplicationService,
        AssessmentPeriod,
        ControlAssessment,
        _InMemoryRecRepo,
    ],
) -> None:
    svc, period, assessment, _rec_repo = wired_service
    await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    stats = await svc.statistics(_ORG, period_id=period.id)
    assert stats["recommended"] == 1
    assert stats["total"] == 1


@pytest.mark.asyncio
async def test_finding_recommendation_not_linkable() -> None:
    """Non-validation sources can be accepted but not linked to ConfirmedEvidenceLink."""
    profile, period, assessment, rec_repo = _build_fixture()
    assess_repo = _InMemoryAssessmentRepo(
        period=period, assessment=assessment, profile=profile
    )
    catalog = MagicMock()
    catalog.list_mappings = AsyncMock(return_value=([], 0))
    session = MagicMock()
    session.begin = MagicMock(return_value=_BeginCtx())
    factory = MagicMock()
    factory.return_value = _SessionCtx(session)

    candidates = [
        EvidenceCandidate(
            reference=EvidenceReference(
                source_kind=EvidenceSourceKind.SECURITY_FINDING,
                source_entity_id="01FINDING000000000000001",
            ),
            raw_score=0.9,
            rationale="finding",
            signals=("finding",),
        )
    ]
    svc = EvidenceRecommendationApplicationService(
        factory,
        candidate_source_factory=lambda _s: [_FakeSource(candidates)],
    )
    svc._recommendation_repo = lambda _s: rec_repo  # type: ignore[method-assign]
    svc._assessment_repo = lambda _s: assess_repo  # type: ignore[method-assign]
    svc._catalog_repo = lambda _s: catalog  # type: ignore[method-assign]

    await svc.generate(
        GenerateRecommendationsCommand(
            organization_id=_ORG,
            period_id=period.id,
            assessment_id=assessment.id,
            generated_by=_ACTOR,
        )
    )
    # May be filtered by policy if confidence too low — force high raw
    if not rec_repo.recs:
        # Manually insert accepted finding recommendation
        from redforge.domain.compliance.recommendation import EvidenceRecommendation

        rec = EvidenceRecommendation.create(
            organization_id=_ORG,
            batch_id=EntityId.generate(),
            assessment_id=assessment.id,
            period_id=period.id,
            requirement_id=assessment.requirement_id,
            framework_key="soc2",
            primary_reference=EvidenceReference(
                source_kind=EvidenceSourceKind.SECURITY_FINDING,
                source_entity_id="01FINDING000000000000001",
            ),
            candidates=tuple(candidates),
            confidence=RecommendationConfidence.parse("high"),
            score=0.8,
            rationale="finding",
            created_by=_ACTOR,
        )
        await rec_repo.save_recommendation(rec)
    rid = next(iter(rec_repo.recs.values())).id
    await svc.accept(
        AcceptRecommendationCommand(
            organization_id=_ORG,
            recommendation_id=rid,
            accepted_by=_ACTOR,
        )
    )
    with pytest.raises(RecommendationNotLinkableError):
        await svc.link_accepted(
            LinkRecommendationCommand(
                organization_id=_ORG,
                recommendation_id=rid,
                linked_by=_ACTOR,
            )
        )

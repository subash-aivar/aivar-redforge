"""PostgreSQL repository proofs for M24 Phase 3 Evidence Recommendations."""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

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
from redforge.infrastructure.database.repositories.compliance.recommendation_repository import (
    SqlAlchemyEvidenceRecommendationRepository,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m24_recommendation_proof"
_DB_URL = os.environ.get(
    "REDFORGE_M24_RECOMMENDATION_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)

_ORG = "01ORG00000000000000000001"
_ACTOR = "01USER000000000000000001"


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _make_rec(
    *,
    batch_id: EntityId,
    assessment_id: EntityId,
    period_id: EntityId,
    evidence_id: str,
) -> EvidenceRecommendation:
    return EvidenceRecommendation.create(
        organization_id=_ORG,
        batch_id=batch_id,
        assessment_id=assessment_id,
        period_id=period_id,
        requirement_id=EntityId.generate(),
        framework_key="soc2",
        primary_reference=EvidenceReference(
            source_kind=EvidenceSourceKind.VALIDATION_EVIDENCE,
            source_entity_id=evidence_id,
        ),
        candidates=(
            EvidenceCandidate(
                reference=EvidenceReference(
                    source_kind=EvidenceSourceKind.VALIDATION_EVIDENCE,
                    source_entity_id=evidence_id,
                ),
                raw_score=0.9,
                rationale="pg proof",
                signals=("integration",),
            ),
        ),
        confidence=RecommendationConfidence.parse("high"),
        score=0.88,
        rationale="pg proof",
        created_by=_ACTOR,
    )


class TestEvidenceRecommendationPersistence:
    async def test_migration_head_is_0043(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            assert result.scalar_one() == "0043"

    async def test_batch_and_recommendation_round_trip(self, session_factory) -> None:
        period_id = EntityId.generate()
        assessment_id = EntityId.generate()
        batch = RecommendationBatch.create(
            organization_id=_ORG,
            period_id=period_id,
            generation_fingerprint=f"fp-{EntityId.generate()}",
            generated_by=_ACTOR,
        )
        evidence_id = f"01EVIDENCE{str(EntityId.generate())[:12]}"
        # Ensure 26-char ULID-like length for entity id constraints
        evidence_id = str(EntityId.generate())
        rec = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment_id,
            period_id=period_id,
            evidence_id=evidence_id,
        )
        batch.record_results(
            recommendation_ids=(rec.id,),
            created_count=1,
            updated_count=0,
            skipped_duplicate_count=0,
        )

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            await repo.save_batch(batch)
            await repo.save_recommendation(rec)

        async with session_factory() as session:
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            loaded_batch = await repo.get_batch(_ORG, batch.id)
            loaded_rec = await repo.get_recommendation(_ORG, rec.id)
            by_fp = await repo.get_batch_by_fingerprint(
                _ORG, batch.generation_fingerprint
            )
            by_dedup = await repo.get_by_dedup_key(_ORG, rec.dedup_key)
            stats = await repo.statistics(_ORG, period_id=period_id)

        assert loaded_batch is not None
        assert loaded_batch.created_count == 1
        assert by_fp is not None
        assert loaded_rec is not None
        assert loaded_rec.status is RecommendationStatus.RECOMMENDED
        assert loaded_rec.confidence.value == "high"
        assert by_dedup is not None
        assert stats["recommended"] >= 1

    async def test_accept_link_persist_and_for_update(self, session_factory) -> None:
        period_id = EntityId.generate()
        assessment_id = EntityId.generate()
        batch = RecommendationBatch.create(
            organization_id=_ORG,
            period_id=period_id,
            generation_fingerprint=f"fp-{EntityId.generate()}",
            generated_by=_ACTOR,
        )
        evidence_id = str(EntityId.generate())
        rec = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment_id,
            period_id=period_id,
            evidence_id=evidence_id,
        )

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            await repo.save_batch(batch)
            await repo.save_recommendation(rec)

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            locked = await repo.get_recommendation_for_update(_ORG, rec.id)
            assert locked is not None
            locked.accept(accepted_by=_ACTOR)
            locked.mark_linked(linked_by=_ACTOR, evidence_id=evidence_id)
            await repo.save_recommendation(locked)

        async with session_factory() as session:
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            loaded = await repo.get_recommendation(_ORG, rec.id)
            history, total = await repo.list_history(_ORG, limit=50, offset=0)

        assert loaded is not None
        assert loaded.status is RecommendationStatus.LINKED
        assert loaded.linked_evidence_id == evidence_id
        assert total >= 1
        assert any(str(h.id) == str(rec.id) for h in history)

    async def test_active_dedup_unique_constraint(self, session_factory) -> None:
        period_id = EntityId.generate()
        assessment_id = EntityId.generate()
        evidence_id = str(EntityId.generate())
        batch = RecommendationBatch.create(
            organization_id=_ORG,
            period_id=period_id,
            generation_fingerprint=f"fp-{EntityId.generate()}",
            generated_by=_ACTOR,
        )
        rec1 = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment_id,
            period_id=period_id,
            evidence_id=evidence_id,
        )
        rec2 = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment_id,
            period_id=period_id,
            evidence_id=evidence_id,
        )
        # Force same dedup_key
        assert rec1.dedup_key == rec2.dedup_key

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            await repo.save_batch(batch)
            await repo.save_recommendation(rec1)

        with pytest.raises(IntegrityError):
            async with session_factory() as session, session.begin():
                repo = SqlAlchemyEvidenceRecommendationRepository(session)
                await repo.save_recommendation(rec2)

    async def test_rejected_allows_new_active_dedup(self, session_factory) -> None:
        period_id = EntityId.generate()
        assessment_id = EntityId.generate()
        evidence_id = str(EntityId.generate())
        batch = RecommendationBatch.create(
            organization_id=_ORG,
            period_id=period_id,
            generation_fingerprint=f"fp-{EntityId.generate()}",
            generated_by=_ACTOR,
        )
        rec1 = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment_id,
            period_id=period_id,
            evidence_id=evidence_id,
        )
        rec1.reject(rejected_by=_ACTOR, rationale="no")

        async with session_factory() as session, session.begin():
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            await repo.save_batch(batch)
            await repo.save_recommendation(rec1)

        rec2 = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment_id,
            period_id=period_id,
            evidence_id=evidence_id,
        )
        async with session_factory() as session, session.begin():
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            await repo.save_recommendation(rec2)

        async with session_factory() as session:
            repo = SqlAlchemyEvidenceRecommendationRepository(session)
            active = await repo.get_by_dedup_key(_ORG, rec2.dedup_key)

        assert active is not None
        assert active.status is RecommendationStatus.RECOMMENDED
        assert str(active.id) == str(rec2.id)


class TestAtomicRecommendationLinking:
    """Prove confirm_evidence_link + mark_linked share one transaction."""

    async def _seed_link_fixture(self, session_factory):
        import json
        from datetime import UTC, datetime, timedelta

        from redforge.application.compliance.recommendation_dtos import (
            LinkRecommendationCommand,
        )
        from redforge.application.compliance.recommendation_service import (
            EvidenceRecommendationApplicationService,
        )
        from redforge.domain.compliance.assessment import (
            AssessmentPeriod,
            ComplianceProfile,
            ControlAssessment,
        )
        from redforge.domain.compliance.value_objects import FrameworkKey
        from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
            SqlAlchemyOrganizationAssessmentRepository,
        )

        org = str(EntityId.generate())
        evidence_id = str(EntityId.generate())
        profile = ComplianceProfile.create(
            organization_id=org,
            name=f"Atomic-{EntityId.generate()}",
            framework_keys=(FrameworkKey.SOC2,),
            created_by=_ACTOR,
        )
        profile.activate(activated_by=_ACTOR, other_active_profiles=())
        start = datetime.now(UTC)
        period = AssessmentPeriod.create(
            organization_id=org,
            profile_id=profile.id,
            name=f"AtomicPeriod-{EntityId.generate()}",
            framework_key=FrameworkKey.SOC2,
            period_start=start,
            period_end=start + timedelta(days=30),
            created_by=_ACTOR,
        )
        period.open(opened_by=_ACTOR)
        assessment = ControlAssessment.create(
            organization_id=org,
            profile_id=profile.id,
            period_id=period.id,
            requirement_id=EntityId.generate(),
            framework_key=FrameworkKey.SOC2,
            created_by=_ACTOR,
        )
        batch = RecommendationBatch.create(
            organization_id=org,
            period_id=period.id,
            generation_fingerprint=f"atomic-{EntityId.generate()}",
            generated_by=_ACTOR,
        )
        rec = _make_rec(
            batch_id=batch.id,
            assessment_id=assessment.id,
            period_id=period.id,
            evidence_id=evidence_id,
        )
        rec.organization_id = org
        rec.accept(accepted_by=_ACTOR)

        evidence_payload = {
            "id": evidence_id,
            "organization_id": org,
            "result": "pass",
            "created_at": datetime.now(UTC).isoformat(),
        }

        async with session_factory() as session, session.begin():
            assess_repo = SqlAlchemyOrganizationAssessmentRepository(session)
            await assess_repo.save_profile(profile)
            await assess_repo.replace_active_framework_claims(
                organization_id=org,
                profile_id=profile.id,
                framework_keys=profile.framework_keys,
            )
            await assess_repo.save_period(period)
            await assess_repo.save_assessment(assessment)
            rec_repo = SqlAlchemyEvidenceRecommendationRepository(session)
            await rec_repo.save_batch(batch)
            await rec_repo.save_recommendation(rec)
            await session.execute(
                text(
                    "INSERT INTO evidence (id, data) VALUES (:id, CAST(:data AS jsonb)) "
                    "ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data"
                ),
                {"id": evidence_id, "data": json.dumps(evidence_payload)},
            )

        svc = EvidenceRecommendationApplicationService(session_factory)
        return org, assessment.id, rec.id, evidence_id, svc, LinkRecommendationCommand

    async def test_link_succeeds_atomically(self, session_factory) -> None:
        from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
            SqlAlchemyOrganizationAssessmentRepository,
        )

        org, assessment_id, rec_id, evidence_id, svc, LinkCmd = (
            await self._seed_link_fixture(session_factory)
        )
        linked = await svc.link_accepted(
            LinkCmd(
                organization_id=org,
                recommendation_id=rec_id,
                linked_by=_ACTOR,
                rationale="atomic success",
            )
        )
        assert linked.status is RecommendationStatus.LINKED
        assert linked.linked_evidence_id == evidence_id

        async with session_factory() as session:
            assess = await SqlAlchemyOrganizationAssessmentRepository(
                session
            ).get_assessment(org, assessment_id)
            rec = await SqlAlchemyEvidenceRecommendationRepository(
                session
            ).get_recommendation(org, rec_id)

        assert assess is not None
        assert any(link.evidence_id == evidence_id for link in assess.evidence_links)
        assert rec is not None
        assert rec.status is RecommendationStatus.LINKED

    async def test_mark_linked_failure_rolls_back_evidence_confirm(
        self, session_factory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from redforge.domain.compliance.recommendation import EvidenceRecommendation
        from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
            SqlAlchemyOrganizationAssessmentRepository,
        )

        org, assessment_id, rec_id, evidence_id, svc, LinkCmd = (
            await self._seed_link_fixture(session_factory)
        )

        def _boom(self: EvidenceRecommendation, **kwargs: object) -> None:
            raise RuntimeError("forced mark_linked failure")

        monkeypatch.setattr(EvidenceRecommendation, "mark_linked", _boom)

        with pytest.raises(RuntimeError, match="forced mark_linked failure"):
            await svc.link_accepted(
                LinkCmd(
                    organization_id=org,
                    recommendation_id=rec_id,
                    linked_by=_ACTOR,
                )
            )

        async with session_factory() as session:
            assess = await SqlAlchemyOrganizationAssessmentRepository(
                session
            ).get_assessment(org, assessment_id)
            rec = await SqlAlchemyEvidenceRecommendationRepository(
                session
            ).get_recommendation(org, rec_id)

        assert assess is not None
        assert all(link.evidence_id != evidence_id for link in assess.evidence_links)
        assert rec is not None
        assert rec.status is RecommendationStatus.ACCEPTED
        assert rec.linked_evidence_id is None

    async def test_missing_evidence_rolls_back_with_no_partial_state(
        self, session_factory
    ) -> None:
        from redforge.domain.compliance.exceptions import EvidenceReferenceNotFoundError
        from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
            SqlAlchemyOrganizationAssessmentRepository,
        )

        org, assessment_id, rec_id, evidence_id, svc, LinkCmd = (
            await self._seed_link_fixture(session_factory)
        )
        async with session_factory() as session, session.begin():
            await session.execute(
                text("DELETE FROM evidence WHERE id = :id"),
                {"id": evidence_id},
            )

        with pytest.raises(EvidenceReferenceNotFoundError):
            await svc.link_accepted(
                LinkCmd(
                    organization_id=org,
                    recommendation_id=rec_id,
                    linked_by=_ACTOR,
                )
            )

        async with session_factory() as session:
            assess = await SqlAlchemyOrganizationAssessmentRepository(
                session
            ).get_assessment(org, assessment_id)
            rec = await SqlAlchemyEvidenceRecommendationRepository(
                session
            ).get_recommendation(org, rec_id)

        assert assess is not None
        assert assess.evidence_links == []
        assert rec is not None
        assert rec.status is RecommendationStatus.ACCEPTED
        assert rec.linked_evidence_id is None

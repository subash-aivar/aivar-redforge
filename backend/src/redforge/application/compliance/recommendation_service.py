"""Evidence Recommendation application service — M24 Phase 3.

Orchestrates AutoLinkingEngine + persistence. Never certifies compliance.
Evidence links are created only after explicit accept → link via the
existing Organization Assessment confirm_evidence_link path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import IntegrityError

from redforge.application.compliance.assessment_dtos import ConfirmEvidenceLinkCommand
from redforge.domain.compliance.exceptions import (
    AssessmentPeriodNotFoundError,
    AssessmentPeriodNotOpenError,
    ControlAssessmentNotFoundError,
    DuplicateEvidenceLinkError,
    DuplicateRecommendationError,
    EvidenceReferenceNotFoundError,
    InvalidRecommendationTransitionError,
    RecommendationNotAcceptedError,
    RecommendationNotFoundError,
    RecommendationNotLinkableError,
)
from redforge.domain.compliance.recommendation import (
    EvidenceRecommendation,
    RecommendationBatch,
)
from redforge.domain.compliance.recommendation_services import (
    AssessmentRecommendationContext,
    AutoLinkingEngine,
    EvidenceCandidateSource,
)
from redforge.domain.compliance.recommendation_value_objects import RecommendationStatus
from redforge.domain.compliance.value_objects import AssessmentPeriodStatus
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.compliance.assessment_service import (
        OrganizationAssessmentService,
    )
    from redforge.application.compliance.recommendation_dtos import (
        AcceptRecommendationCommand,
        GenerateRecommendationsCommand,
        LinkRecommendationCommand,
        RejectRecommendationCommand,
    )
    from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
        SqlAlchemyOrganizationAssessmentRepository,
    )
    from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
        SqlAlchemyControlCatalogRepository,
    )
    from redforge.infrastructure.database.repositories.compliance.recommendation_repository import (
        SqlAlchemyEvidenceRecommendationRepository,
    )


class EvidenceRecommendationApplicationService:
    """Org-scoped recommendation generation and human decision workflow."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        assessment_service: OrganizationAssessmentService | None = None,
        engine: AutoLinkingEngine | None = None,
        candidate_source_factory: (
            Callable[[AsyncSession], Sequence[EvidenceCandidateSource]] | None
        ) = None,
    ) -> None:
        self._session_factory = session_factory
        self._assessment_service = assessment_service
        self._engine = engine or AutoLinkingEngine()
        self._candidate_source_factory = candidate_source_factory

    def _recommendation_repo(
        self, session: AsyncSession
    ) -> SqlAlchemyEvidenceRecommendationRepository:
        from redforge.infrastructure.database.repositories.compliance import (
            recommendation_repository as rec_repo_mod,
        )

        return rec_repo_mod.SqlAlchemyEvidenceRecommendationRepository(session)

    def _assessment_repo(
        self, session: AsyncSession
    ) -> SqlAlchemyOrganizationAssessmentRepository:
        from redforge.infrastructure.database.repositories.compliance.assessment_repository import (
            SqlAlchemyOrganizationAssessmentRepository as Repo,
        )

        return Repo(session)

    def _catalog_repo(self, session: AsyncSession) -> SqlAlchemyControlCatalogRepository:
        from redforge.infrastructure.database.repositories.compliance.catalog_repository import (
            SqlAlchemyControlCatalogRepository as Repo,
        )

        return Repo(session)

    def _sources(self, session: AsyncSession) -> Sequence[EvidenceCandidateSource]:
        if self._candidate_source_factory is not None:
            return self._candidate_source_factory(session)
        from redforge.infrastructure.compliance.recommendation_candidate_sources import (
            default_candidate_sources,
        )

        return default_candidate_sources(session)  # type: ignore[return-value]

    def _org_assessment_service(self) -> OrganizationAssessmentService:
        if self._assessment_service is not None:
            return self._assessment_service
        from redforge.application.compliance.assessment_service import (
            OrganizationAssessmentService,
        )

        return OrganizationAssessmentService(self._session_factory)

    async def generate(
        self, command: GenerateRecommendationsCommand
    ) -> RecommendationBatch:
        async with self._session_factory() as session, session.begin():
            assess_repo = self._assessment_repo(session)
            rec_repo = self._recommendation_repo(session)
            catalog = self._catalog_repo(session)

            period = await assess_repo.get_period(
                command.organization_id, command.period_id
            )
            if period is None:
                raise AssessmentPeriodNotFoundError(str(command.period_id))
            if period.status is not AssessmentPeriodStatus.OPEN:
                raise AssessmentPeriodNotOpenError(
                    str(period.id),
                    f"status is '{period.status.value}'",
                )

            if command.assessment_id is not None:
                assessment = await assess_repo.get_assessment(
                    command.organization_id, command.assessment_id
                )
                if assessment is None:
                    raise ControlAssessmentNotFoundError(str(command.assessment_id))
                if assessment.period_id != period.id:
                    raise ControlAssessmentNotFoundError(str(command.assessment_id))
                assessments = [assessment]
            else:
                assessments = await assess_repo.list_assessments(
                    command.organization_id, period_id=period.id
                )

            # Collect all candidates first for fingerprint idempotency
            sources = self._sources(session)
            all_tokens: list[str] = []
            per_assessment: list[
                tuple[Any, AssessmentRecommendationContext, list[Any]]
            ] = []

            for assessment in assessments:
                confirmed = frozenset(
                    link.evidence_id for link in assessment.evidence_links
                )
                mapping_hint: str | None = None
                # Best-effort: first active mapping involving this requirement
                mappings, _ = await catalog.list_mappings(
                    source_framework_key=None,
                    target_framework_key=None,
                    active_only=True,
                    limit=200,
                    offset=0,
                )
                for mapping in mappings:
                    if str(mapping.source_requirement_id) == str(
                        assessment.requirement_id
                    ) or str(mapping.target_requirement_id) == str(
                        assessment.requirement_id
                    ):
                        mapping_hint = mapping.confidence.value
                        break

                context = AssessmentRecommendationContext(
                    organization_id=command.organization_id,
                    assessment_id=assessment.id,
                    period_id=period.id,
                    requirement_id=assessment.requirement_id,
                    framework_key=assessment.framework_key.value
                    if hasattr(assessment.framework_key, "value")
                    else str(assessment.framework_key),
                    existing_confirmed_evidence_ids=confirmed,
                    mapping_confidence_hint=mapping_hint,
                )
                candidates: list[Any] = []
                for source in sources:
                    found = await source.find_candidates(
                        organization_id=command.organization_id,
                        assessment_id=assessment.id,
                        period_id=period.id,
                        requirement_id=assessment.requirement_id,
                        framework_key=context.framework_key,
                        existing_confirmed_evidence_ids=confirmed,
                    )
                    candidates.extend(found)
                all_tokens.extend(c.reference.dedup_token() for c in candidates)
                per_assessment.append((assessment, context, candidates))

            fingerprint = self._engine.generation_fingerprint(
                organization_id=command.organization_id,
                period_id=period.id,
                assessment_id=command.assessment_id,
                candidate_tokens=all_tokens,
            )
            existing_batch = await rec_repo.get_batch_by_fingerprint(
                command.organization_id, fingerprint
            )
            if existing_batch is not None:
                return existing_batch

            batch = RecommendationBatch.create(
                organization_id=command.organization_id,
                period_id=period.id,
                assessment_id=command.assessment_id,
                generation_fingerprint=fingerprint,
                generated_by=command.generated_by,
            )

            created_all: list[EvidenceRecommendation] = []
            updated_all: list[EvidenceRecommendation] = []
            skipped_total = 0
            result_ids: list[EntityId] = []

            for _assessment, context, candidates in per_assessment:
                existing, _ = await rec_repo.list_recommendations(
                    command.organization_id,
                    assessment_id=context.assessment_id,
                    limit=500,
                    offset=0,
                )
                result = self._engine.recommend_for_assessment(
                    batch=batch,
                    context=context,
                    candidates=candidates,
                    existing_recommendations=list(existing),
                    created_by=command.generated_by,
                )
                for rec in result.created:
                    try:
                        await rec_repo.save_recommendation(rec)
                    except IntegrityError as exc:
                        # Concurrent insert of same active dedup_key
                        raise DuplicateRecommendationError(
                            rec.dedup_key, str(rec.id)
                        ) from exc
                    rec.collect_events()
                    created_all.append(rec)
                    result_ids.append(rec.id)
                for rec in result.updated:
                    await rec_repo.save_recommendation(rec)
                    rec.collect_events()
                    updated_all.append(rec)
                    result_ids.append(rec.id)
                skipped_total += result.skipped_duplicate_count

            batch.record_results(
                recommendation_ids=tuple(result_ids),
                created_count=len(created_all),
                updated_count=len(updated_all),
                skipped_duplicate_count=skipped_total,
            )
            try:
                await rec_repo.save_batch(batch)
            except IntegrityError:
                # Concurrent identical generation — return winner
                raced = await rec_repo.get_batch_by_fingerprint(
                    command.organization_id, fingerprint
                )
                if raced is not None:
                    return raced
                raise
            batch.collect_events()
            return batch

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
        async with self._session_factory() as session:
            return await self._recommendation_repo(session).list_recommendations(
                organization_id,
                period_id=period_id,
                assessment_id=assessment_id,
                status=status,
                limit=limit,
                offset=offset,
            )

    async def get_recommendation(
        self, organization_id: str, recommendation_id: EntityId
    ) -> EvidenceRecommendation:
        async with self._session_factory() as session:
            rec = await self._recommendation_repo(session).get_recommendation(
                organization_id, recommendation_id
            )
        if rec is None:
            raise RecommendationNotFoundError(str(recommendation_id))
        return rec

    async def accept(
        self, command: AcceptRecommendationCommand
    ) -> EvidenceRecommendation:
        async with self._session_factory() as session, session.begin():
            repo = self._recommendation_repo(session)
            rec = await repo.get_recommendation_for_update(
                command.organization_id, command.recommendation_id
            )
            if rec is None:
                raise RecommendationNotFoundError(str(command.recommendation_id))
            period = await self._assessment_repo(session).get_period(
                command.organization_id, rec.period_id
            )
            if period is None:
                raise AssessmentPeriodNotFoundError(str(rec.period_id))
            period.assert_open()
            try:
                rec.accept(
                    accepted_by=command.accepted_by, rationale=command.rationale
                )
            except InvalidRecommendationTransitionError:
                raise
            await repo.save_recommendation(rec)
            rec.collect_events()
            return rec

    async def reject(
        self, command: RejectRecommendationCommand
    ) -> EvidenceRecommendation:
        async with self._session_factory() as session, session.begin():
            repo = self._recommendation_repo(session)
            rec = await repo.get_recommendation_for_update(
                command.organization_id, command.recommendation_id
            )
            if rec is None:
                raise RecommendationNotFoundError(str(command.recommendation_id))
            period = await self._assessment_repo(session).get_period(
                command.organization_id, rec.period_id
            )
            if period is None:
                raise AssessmentPeriodNotFoundError(str(rec.period_id))
            if period.status is AssessmentPeriodStatus.OPEN:
                # Allow reject on open periods; closed periods may still reject
                # outstanding recommended/accepted items for audit closure.
                pass
            rec.reject(rejected_by=command.rejected_by, rationale=command.rationale)
            await repo.save_recommendation(rec)
            rec.collect_events()
            return rec

    async def link_accepted(
        self, command: LinkRecommendationCommand
    ) -> EvidenceRecommendation:
        """Atomically confirm evidence on the assessment and mark recommendation linked.

        Evidence confirmation and recommendation state transition share one
        database transaction — both commit or both roll back. Never auto-certifies.
        Requires prior accept. Only linkable source kinds.
        """
        async with self._session_factory() as session, session.begin():
            repo = self._recommendation_repo(session)
            locked = await repo.get_recommendation_for_update(
                command.organization_id, command.recommendation_id
            )
            if locked is None:
                raise RecommendationNotFoundError(str(command.recommendation_id))
            if locked.status is RecommendationStatus.LINKED:
                return locked
            if locked.status is not RecommendationStatus.ACCEPTED:
                raise RecommendationNotAcceptedError(
                    str(locked.id), locked.status.value
                )

            try:
                evidence_id = locked.linkable_evidence_id()
            except RecommendationNotLinkableError:
                raise

            try:
                await self._org_assessment_service().confirm_evidence_link_in_session(
                    session,
                    ConfirmEvidenceLinkCommand(
                        organization_id=command.organization_id,
                        assessment_id=locked.assessment_id,
                        evidence_id=evidence_id,
                        confirmed_by=command.linked_by,
                        rationale=command.rationale
                        or f"Linked from recommendation {locked.id}",
                    ),
                )
            except DuplicateEvidenceLinkError:
                # Evidence already confirmed on this assessment — still
                # complete the recommendation transition in the same TX.
                pass
            except EvidenceReferenceNotFoundError:
                raise

            locked.mark_linked(linked_by=command.linked_by, evidence_id=evidence_id)
            await repo.save_recommendation(locked)
            locked.collect_events()
            return locked

    async def history(
        self,
        organization_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[EvidenceRecommendation], int]:
        async with self._session_factory() as session:
            return await self._recommendation_repo(session).list_history(
                organization_id, limit=limit, offset=offset
            )

    async def statistics(
        self, organization_id: str, *, period_id: EntityId | None = None
    ) -> dict[str, int]:
        async with self._session_factory() as session:
            return await self._recommendation_repo(session).statistics(
                organization_id, period_id=period_id
            )

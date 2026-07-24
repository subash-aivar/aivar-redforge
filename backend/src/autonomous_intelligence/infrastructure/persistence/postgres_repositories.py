"""PostgreSQL repositories for autonomous_intelligence.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.repositories.i_repositories import (
    IAutonomousOperationsPolicyRepository,
    IIntelligenceSuggestionRepository,
    IOptimizationModelRepository,
    ISuggestionOutcomeRepository,
)
from autonomous_intelligence.domain.value_objects.enums import (
    ModelStatus,
    OutcomeType,
    SuggestionPriority,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import (
    ModelId,
    SuggestionId,
    TenantId,
)
from autonomous_intelligence.infrastructure.persistence.models.orm_models import (
    AutonomousOperationsPolicyModel,
    IntelligenceSuggestionModel,
    OptimizationModelModel,
    SuggestionOutcomeModel,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ── IntelligenceSuggestion ───────────────────────────────────────────────────


def _suggestion_to_row(s: IntelligenceSuggestion) -> IntelligenceSuggestionModel:
    return IntelligenceSuggestionModel(
        id=s.suggestion_id.value,
        tenant_id=s.tenant_id.value,
        target_type=s.target_ref.target_type.value,
        target_context=s.target_ref.target_context,
        target_id=s.target_ref.target_id,
        status=s.status.value,
        confidence_score=s.evidence.confidence_score,
        model_id=s.evidence.model_id,
        model_version=s.evidence.model_version,
        rationale_summary=s.evidence.rationale_summary,
        supporting_signal_refs=list(s.evidence.supporting_signal_refs),
        proposed_change_payload=dict(s.target_ref.proposed_change_payload),
        priority=s.priority.value,
        created_at=s.created_at,
        review_deadline_at=s.review_deadline_at,
        reviewed_at=s.reviewed_at,
        approved_by=s.approved_by,
        rejected_by=s.rejected_by,
        rejection_reason=s.rejection_reason,
        version=s.version,
    )


def _row_to_suggestion(row: IntelligenceSuggestionModel) -> IntelligenceSuggestion:
    target_ref = SuggestionTargetRef(
        target_context=row.target_context,
        target_id=row.target_id,
        target_type=SuggestionTargetType(row.target_type),
        proposed_change_payload=dict(row.proposed_change_payload),
    )
    evidence = SuggestionEvidence(
        model_id=row.model_id,
        model_version=row.model_version,
        confidence_score=row.confidence_score,
        supporting_signal_refs=tuple(row.supporting_signal_refs or []),
        rationale_summary=row.rationale_summary,
        generated_at=row.created_at,
    )
    return IntelligenceSuggestion(
        suggestion_id=SuggestionId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        target_ref=target_ref,
        evidence=evidence,
        status=SuggestionStatus(row.status),
        created_at=row.created_at,
        review_deadline_at=row.review_deadline_at,
        priority=SuggestionPriority(row.priority),
        approved_by=row.approved_by,
        rejected_by=row.rejected_by,
        rejection_reason=row.rejection_reason,
        reviewed_at=row.reviewed_at,
        version=row.version,
    )


class PgIntelligenceSuggestionRepository(IIntelligenceSuggestionRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, suggestion: IntelligenceSuggestion, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_suggestion_to_row(suggestion))
            await session.commit()

    async def find_by_id(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> IntelligenceSuggestion | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(IntelligenceSuggestionModel).where(
                        IntelligenceSuggestionModel.tenant_id == tenant_id.value,
                        IntelligenceSuggestionModel.id == suggestion_id,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_suggestion(row) if row is not None else None

    async def find_pending_review(
        self, tenant_id: TenantId, target_type: SuggestionTargetType | None, limit: int
    ) -> list[IntelligenceSuggestion]:
        async with self._session_factory() as session:
            stmt = select(IntelligenceSuggestionModel).where(
                IntelligenceSuggestionModel.tenant_id == tenant_id.value,
                IntelligenceSuggestionModel.status == SuggestionStatus.PENDING_REVIEW.value,
            )
            if target_type is not None:
                stmt = stmt.where(IntelligenceSuggestionModel.target_type == target_type.value)
            stmt = stmt.limit(limit)
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_suggestion(r) for r in rows]

    async def find_approved_pending_application(
        self, tenant_id: TenantId
    ) -> list[IntelligenceSuggestion]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(IntelligenceSuggestionModel).where(
                        IntelligenceSuggestionModel.tenant_id == tenant_id.value,
                        IntelligenceSuggestionModel.status == SuggestionStatus.APPROVED.value,
                    )
                )
            ).scalars().all()
            return [_row_to_suggestion(r) for r in rows]

    async def find_expired_pending(self, cutoff: datetime) -> list[IntelligenceSuggestion]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(IntelligenceSuggestionModel).where(
                        IntelligenceSuggestionModel.status
                        == SuggestionStatus.PENDING_REVIEW.value,
                        IntelligenceSuggestionModel.review_deadline_at < cutoff,
                    )
                )
            ).scalars().all()
            return [_row_to_suggestion(r) for r in rows]


# ── OptimizationModel ────────────────────────────────────────────────────────


def _model_to_row(m: OptimizationModel) -> OptimizationModelModel:
    return OptimizationModelModel(
        id=m.model_id.value,
        tenant_id=m.tenant_id.value,
        target_type=m.target_type.value,
        model_version=m.model_version,
        status=m.status.value,
        accuracy_metrics=dict(m.accuracy_metrics),
        conformity_assessment_ref=m.conformity_assessment_ref,
        feedback_sample_count=m.feedback_sample_count,
        retraining_threshold=m.retraining_threshold,
        created_at=m.created_at,
        deployed_at=m.deployed_at,
    )


def _row_to_model(row: OptimizationModelModel) -> OptimizationModel:
    return OptimizationModel(
        model_id=ModelId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        target_type=SuggestionTargetType(row.target_type),
        model_version=row.model_version,
        status=ModelStatus(row.status),
        accuracy_metrics=dict(row.accuracy_metrics),
        conformity_assessment_ref=row.conformity_assessment_ref,
        feedback_sample_count=row.feedback_sample_count,
        retraining_threshold=row.retraining_threshold,
        created_at=row.created_at,
        deployed_at=row.deployed_at,
    )


class PgOptimizationModelRepository(IOptimizationModelRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, model: OptimizationModel, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_model_to_row(model))
            await session.commit()

    async def find_deployed(
        self, tenant_id: TenantId, target_type: SuggestionTargetType
    ) -> OptimizationModel | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(OptimizationModelModel).where(
                        OptimizationModelModel.tenant_id == tenant_id.value,
                        OptimizationModelModel.target_type == target_type.value,
                        OptimizationModelModel.status == ModelStatus.DEPLOYED.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_model(row) if row is not None else None

    async def find_by_id(self, model_id: str, tenant_id: TenantId) -> OptimizationModel | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(OptimizationModelModel).where(
                        OptimizationModelModel.tenant_id == tenant_id.value,
                        OptimizationModelModel.id == model_id,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_model(row) if row is not None else None


# ── SuggestionOutcome (append-only) ─────────────────────────────────────────


class PgSuggestionOutcomeRepository(ISuggestionOutcomeRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(self, outcome: SuggestionOutcome) -> None:
        async with self._session_factory() as session:
            session.add(
                SuggestionOutcomeModel(
                    id=outcome.outcome_id,
                    suggestion_id=outcome.suggestion_id,
                    tenant_id=outcome.tenant_id.value,
                    target_type=outcome.target_type.value,
                    outcome_type=outcome.outcome_type.value,
                    measurement_window_days=outcome.measurement_window_days,
                    baseline_metric=outcome.baseline_metric,
                    observed_metric=outcome.observed_metric,
                    delta=outcome.delta,
                    measured_at=outcome.measured_at,
                )
            )
            await session.commit()

    async def update_measurement(self, outcome: SuggestionOutcome, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(SuggestionOutcomeModel).where(
                        SuggestionOutcomeModel.tenant_id == tenant_id.value,
                        SuggestionOutcomeModel.id == outcome.outcome_id,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return
            row.outcome_type = outcome.outcome_type.value
            row.observed_metric = outcome.observed_metric
            row.delta = outcome.delta
            row.measured_at = outcome.measured_at
            await session.commit()

    async def find_for_suggestion(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> list[SuggestionOutcome]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(SuggestionOutcomeModel).where(
                        SuggestionOutcomeModel.tenant_id == tenant_id.value,
                        SuggestionOutcomeModel.suggestion_id == suggestion_id,
                    )
                )
            ).scalars().all()
            return [_row_to_outcome(r) for r in rows]

    async def find_pending_measurement(
        self, cutoff: datetime, tenant_id: TenantId
    ) -> list[SuggestionOutcome]:
        del cutoff  # in-memory repo ignores it too — matched for parity
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(SuggestionOutcomeModel).where(
                        SuggestionOutcomeModel.tenant_id == tenant_id.value,
                        SuggestionOutcomeModel.outcome_type == OutcomeType.PENDING.value,
                    )
                )
            ).scalars().all()
            return [_row_to_outcome(r) for r in rows]


def _row_to_outcome(row: SuggestionOutcomeModel) -> SuggestionOutcome:
    return SuggestionOutcome(
        outcome_id=row.id,
        suggestion_id=row.suggestion_id,
        tenant_id=TenantId.from_uuid(row.tenant_id),
        target_type=SuggestionTargetType(row.target_type),
        outcome_type=OutcomeType(row.outcome_type),
        measurement_window_days=row.measurement_window_days,
        baseline_metric=row.baseline_metric,
        observed_metric=row.observed_metric,
        delta=row.delta,
        measured_at=row.measured_at,
    )


# ── AutonomousOperationsPolicy ───────────────────────────────────────────────


class PgAutonomousOperationsPolicyRepository(IAutonomousOperationsPolicyRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_or_create_default(self, tenant_id: TenantId) -> AutonomousOperationsPolicy:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AutonomousOperationsPolicyModel).where(
                        AutonomousOperationsPolicyModel.tenant_id == tenant_id.value
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                return _row_to_policy(row)

            policy = AutonomousOperationsPolicy.default(tenant_id)
            session.add(_policy_to_row(policy))
            await session.commit()
            return policy

    async def save(self, policy: AutonomousOperationsPolicy, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_policy_to_row(policy))
            await session.commit()


def _policy_to_row(policy: AutonomousOperationsPolicy) -> AutonomousOperationsPolicyModel:
    return AutonomousOperationsPolicyModel(
        tenant_id=policy.tenant_id.value,
        kill_switch_active=policy.kill_switch_active,
        review_required=policy.review_required,
        min_confidence_by_type={
            k.value: v for k, v in policy.min_confidence_by_type.items()
        },
        enabled_target_types=[t.value for t in policy.enabled_target_types],
        updated_at=policy.updated_at,
    )


def _row_to_policy(row: AutonomousOperationsPolicyModel) -> AutonomousOperationsPolicy:
    return AutonomousOperationsPolicy(
        tenant_id=TenantId.from_uuid(row.tenant_id),
        kill_switch_active=row.kill_switch_active,
        min_confidence_by_type={
            SuggestionTargetType(k): float(v) for k, v in (row.min_confidence_by_type or {}).items()
        },
        enabled_target_types=[SuggestionTargetType(t) for t in (row.enabled_target_types or [])],
        review_required=row.review_required,
        updated_at=row.updated_at,
    )

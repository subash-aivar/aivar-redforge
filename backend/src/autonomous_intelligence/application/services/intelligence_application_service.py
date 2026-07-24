"""CQRS application service for autonomous_intelligence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from autonomous_intelligence.application._auth import require_any
from autonomous_intelligence.application.commands.intelligence_commands import (
    ApproveSuggestion,
    CreateIntelligenceSuggestion,
    DeployOptimizationModel,
    MarkSuggestionApplied,
    RejectSuggestion,
    TrainOptimizationModel,
)
from autonomous_intelligence.application.dtos.intelligence_dtos import (
    ModelDTO,
    SuggestionDTO,
)
from autonomous_intelligence.application.exceptions import ApplicationNotFoundError
from autonomous_intelligence.application.read_models.read_models import (
    AcceptanceRateReadModel,
    ModelAccuracyReadModel,
    PolicyReadModel,
    SuggestionQueueReadModel,
)
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.services.autonomy_boundary_service import (
    AutonomyBoundaryService,
)
from autonomous_intelligence.domain.services.model_governance_service import ModelGovernanceService
from autonomous_intelligence.domain.services.suggestion_generation_service import (
    SuggestionGenerationService,
)
from autonomous_intelligence.domain.services.suggestion_review_service import (
    SuggestionReviewService,
)
from autonomous_intelligence.domain.value_objects.enums import (
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class IntelligenceApplicationService:
    def __init__(
        self,
        suggestions: Any,
        models: Any,
        outcomes: Any,
        policies: Any,
        llm: Any,
        event_sink: list[Any] | None = None,
        audit_log: list[dict[str, Any]] | None = None,
    ) -> None:
        self._suggestions = suggestions
        self._models = models
        self._outcomes = outcomes
        self._policies = policies
        self._llm = llm
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._audit: list[dict[str, Any]] = audit_log if audit_log is not None else []
        self._gen = SuggestionGenerationService()
        self._review = SuggestionReviewService()
        self._boundary = AutonomyBoundaryService()
        self._governance = ModelGovernanceService()

    def _tenant(self, value: UUID) -> TenantId:
        if isinstance(value, TenantId):
            return value
        return TenantId.from_string(str(value))

    def _to_dto(self, s: Any) -> SuggestionDTO:
        return SuggestionDTO(
            str(s.suggestion_id),
            str(s.tenant_id),
            s.target_type.value,
            s.status.value,
            s.evidence.confidence_score,
            s.evidence.rationale_summary,
            s.evidence.model_id,
            s.evidence.model_version,
            s.review_deadline_at.isoformat(),
        )

    async def create_suggestion(self, cmd: CreateIntelligenceSuggestion) -> SuggestionDTO:
        require_any(
            cmd.roles,
            "ai:operator",
            "soc:detection_engineer",
            "soc:security_engineer",
            "system",
        )
        tenant = self._tenant(cmd.tenant_id)
        policy = await self._policies.get_or_create_default(tenant)
        target_type = SuggestionTargetType(cmd.target_type)
        evidence = SuggestionEvidence(
            model_id=cmd.model_id,
            model_version=cmd.model_version,
            confidence_score=cmd.confidence_score,
            supporting_signal_refs=cmd.supporting_signal_refs,
            rationale_summary=cmd.rationale_summary,
            generated_at=datetime.now(UTC),
        )
        target_ref = SuggestionTargetRef(
            target_context=cmd.target_context,
            target_id=cmd.target_id,
            target_type=target_type,
            proposed_change_payload=cmd.proposed_change_payload,
        )
        suggestion = self._gen.create_if_eligible(
            tenant,
            target_ref,
            evidence,
            min_confidence=policy.min_confidence(target_type),
            kill_switch_active=policy.kill_switch_active,
            enabled=policy.allows(target_type),
        )
        await self._suggestions.save(suggestion, tenant)
        self._events.extend(suggestion.pop_events())
        return self._to_dto(suggestion)

    async def approve(self, cmd: ApproveSuggestion) -> SuggestionDTO:
        tenant = self._tenant(cmd.tenant_id)
        suggestion = await self._suggestions.find_by_id(cmd.suggestion_id, tenant)
        if suggestion is None:
            raise ApplicationNotFoundError("suggestion not found")
        self._review.approve(suggestion, tenant, cmd.approved_by, cmd.roles)
        await self._suggestions.save(suggestion, tenant)
        self._events.extend(suggestion.pop_events())
        return self._to_dto(suggestion)

    async def reject(self, cmd: RejectSuggestion) -> SuggestionDTO:
        tenant = self._tenant(cmd.tenant_id)
        suggestion = await self._suggestions.find_by_id(cmd.suggestion_id, tenant)
        if suggestion is None:
            raise ApplicationNotFoundError("suggestion not found")
        self._review.reject(suggestion, tenant, cmd.rejected_by, cmd.rejection_reason, cmd.roles)
        await self._suggestions.save(suggestion, tenant)
        self._events.extend(suggestion.pop_events())
        return self._to_dto(suggestion)

    async def mark_applied(self, cmd: MarkSuggestionApplied) -> SuggestionDTO:
        tenant = self._tenant(cmd.tenant_id)
        suggestion = await self._suggestions.find_by_id(cmd.suggestion_id, tenant)
        if suggestion is None:
            raise ApplicationNotFoundError("suggestion not found")
        suggestion.mark_applied(tenant, cmd.target_context_ref)
        await self._suggestions.save(suggestion, tenant)
        self._events.extend(suggestion.pop_events())
        return self._to_dto(suggestion)

    async def train_model(self, cmd: TrainOptimizationModel) -> ModelDTO:
        require_any(cmd.roles, "ai:ml_engineer", "incident:ciso", "system")
        tenant = self._tenant(cmd.tenant_id)
        model = OptimizationModel.start_training(
            tenant,
            SuggestionTargetType(cmd.target_type),
            cmd.model_id,
            cmd.model_version,
        )
        await self._models.save(model, tenant)
        return ModelDTO(
            str(model.model_id),
            str(tenant),
            model.target_type.value,
            model.model_version,
            model.status.value,
            dict(model.accuracy_metrics),
            model.feedback_sample_count,
        )

    async def deploy_model(self, cmd: DeployOptimizationModel) -> ModelDTO:
        require_any(cmd.roles, "ai:ml_engineer", "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        model = await self._models.find_by_id(cmd.model_id, tenant)
        if model is None:
            raise ApplicationNotFoundError("model not found")
        if model.status.value == "training":
            model.mark_validating(cmd.accuracy_metrics)
        elif model.status.value == "validating":
            # Allow redeploy attempts with updated validation metrics.
            model.accuracy_metrics = dict(cmd.accuracy_metrics)
        self._governance.deploy(model, tenant, cmd.conformity_assessment_ref)
        # deprecate prior deployed
        prior = await self._models.find_deployed(tenant, model.target_type)
        if prior and str(prior.model_id) != str(model.model_id):
            self._governance.deprecate(prior, tenant, model.model_version)
            await self._models.save(prior, tenant)
            self._events.extend(prior.pop_events())
        await self._models.save(model, tenant)
        self._events.extend(model.pop_events())
        return ModelDTO(
            str(model.model_id),
            str(tenant),
            model.target_type.value,
            model.model_version,
            model.status.value,
            dict(model.accuracy_metrics),
            model.feedback_sample_count,
        )

    async def get_queue(
        self,
        tenant_id: TenantId,
        roles: tuple[str, ...],
        target_type: str | None = None,
        limit: int = 50,
    ) -> list[SuggestionQueueReadModel]:
        require_any(
            roles,
            "soc:detection_engineer",
            "red_team:architect",
            "soc:security_engineer",
            "vuln:manager",
            "ai:operator",
            "playbook:analyst",
        )
        tenant = self._tenant(tenant_id)
        tt = SuggestionTargetType(target_type) if target_type else None
        rows = await self._suggestions.find_pending_review(tenant, tt, limit)
        rows = sorted(rows, key=lambda s: s.evidence.confidence_score, reverse=True)
        return [
            SuggestionQueueReadModel(
                str(s.suggestion_id),
                s.target_type.value,
                s.evidence.confidence_score,
                s.evidence.rationale_summary,
                s.target_ref.target_context,
                str(s.target_ref.target_id) if s.target_ref.target_id else None,
                s.evidence.model_id,
                s.evidence.model_version,
                s.created_at,
                s.review_deadline_at,
            )
            for s in rows
        ]

    async def get_acceptance_rate(
        self, tenant_id: TenantId, roles: tuple[str, ...]
    ) -> list[AcceptanceRateReadModel]:
        require_any(roles, "ai:operator", "incident:ciso", "playbook:analyst")
        tenant = self._tenant(tenant_id)
        out: list[AcceptanceRateReadModel] = []
        for tt in SuggestionTargetType:
            pending = await self._suggestions.find_pending_review(tenant, tt, 1000)
            # simplified: use event sink counts in container for trends
            total = len(pending)
            out.append(AcceptanceRateReadModel(tt.value, total, 0, 0, 0, 0.0, 0.0))
        return out

    async def get_model_accuracy(
        self, tenant_id: TenantId, roles: tuple[str, ...]
    ) -> list[ModelAccuracyReadModel]:
        require_any(roles, "ai:ml_engineer", "ai:operator", "incident:ciso")
        tenant = self._tenant(tenant_id)
        results: list[ModelAccuracyReadModel] = []
        for tt in SuggestionTargetType:
            model = await self._models.find_deployed(tenant, tt)
            if model is None:
                continue
            results.append(
                ModelAccuracyReadModel(
                    str(model.model_id),
                    tt.value,
                    model.model_version,
                    model.status.value,
                    model.deployed_at,
                    model.accuracy_metrics.get("precision"),
                    model.accuracy_metrics.get("recall"),
                    model.accuracy_metrics.get("rank_correlation"),
                    model.feedback_sample_count,
                    0.0,
                )
            )
        return results

    async def get_policy(self, tenant_id: TenantId, roles: tuple[str, ...]) -> PolicyReadModel:
        require_any(roles, "ai:operator", "incident:ciso", "playbook:analyst")
        policy = await self._policies.get_or_create_default(self._tenant(tenant_id))
        return PolicyReadModel(
            str(policy.tenant_id),
            policy.kill_switch_active,
            policy.review_required,
            [t.value for t in policy.enabled_target_types],
            {k.value: v for k, v in policy.min_confidence_by_type.items()},
        )

    async def get_suggestion(
        self, tenant_id: TenantId, suggestion_id: UUID, roles: tuple[str, ...]
    ) -> SuggestionDTO:
        require_any(roles, "ai:operator", "playbook:analyst", "soc:detection_engineer")
        s = await self._suggestions.find_by_id(suggestion_id, self._tenant(tenant_id))
        if s is None:
            raise ApplicationNotFoundError("suggestion not found")
        return self._to_dto(s)

    def record_llm_audit(
        self, tenant_id: str, model_id: str, prompt_token_count: int, completion_token_count: int
    ) -> None:
        self._audit.append(
            {
                "tenant_id": tenant_id,
                "model_id": model_id,
                "prompt_token_count": prompt_token_count,
                "completion_token_count": completion_token_count,
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )

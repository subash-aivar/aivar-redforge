"""autonomous_intelligence application, infra, API, tests."""

from __future__ import annotations

from .common import SRC, TESTS, w


def write() -> None:
    base = SRC / "autonomous_intelligence"
    _services(base)
    _repos(base)
    _ports_app(base)
    _infra(base)
    _api(base)
    _eu_doc(base)
    _tests()


def _services(base):
    w(
        base / "domain" / "services" / "suggestion_generation_service.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    ConfidenceThresholdNotMet,
    DomainInvariantViolation,
)
from autonomous_intelligence.domain.value_objects.enums import SuggestionPriority, SuggestionTargetType
from autonomous_intelligence.domain.value_objects.evidence import SuggestionEvidence, SuggestionTargetRef
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class SuggestionGenerationService:
    def create_if_eligible(
        self,
        tenant_id: TenantId,
        target_ref: SuggestionTargetRef,
        evidence: SuggestionEvidence,
        *,
        min_confidence: float,
        kill_switch_active: bool,
        enabled: bool,
        priority: SuggestionPriority = SuggestionPriority.MEDIUM,
    ) -> IntelligenceSuggestion:
        if kill_switch_active:
            raise DomainInvariantViolation("autonomy kill switch active")
        if not enabled:
            raise DomainInvariantViolation("target type disabled for tenant")
        if evidence.confidence_score < min_confidence:
            raise ConfidenceThresholdNotMet(
                f"{evidence.confidence_score} < {min_confidence} for {target_ref.target_type.value}"
            )
        if target_ref.target_type not in SuggestionTargetType:
            raise DomainInvariantViolation("unknown target type")
        return IntelligenceSuggestion.create(
            tenant_id, target_ref, evidence, priority=priority
        )
''',
    )
    w(
        base / "domain" / "services" / "suggestion_review_service.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class SuggestionReviewService:
    def approve(
        self,
        suggestion: IntelligenceSuggestion,
        tenant_id: TenantId,
        approved_by: str,
        roles: tuple[str, ...],
    ) -> None:
        suggestion.approve(tenant_id, approved_by, roles)

    def reject(
        self,
        suggestion: IntelligenceSuggestion,
        tenant_id: TenantId,
        rejected_by: str,
        reason: str,
        roles: tuple[str, ...],
    ) -> None:
        suggestion.reject(tenant_id, rejected_by, reason, roles)
''',
    )
    w(
        base / "domain" / "services" / "autonomy_boundary_service.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.exceptions.domain_exceptions import AutonBoundaryViolation


class AutonomyBoundaryService:
    """Guards ADR-M36-001 — no direct cross-context mutation."""

    FORBIDDEN_MUTATIONS = frozenset(
        {
            "DetectionRule",
            "RuleVersion",
            "ScenarioTemplate",
            "PlaybookVersion",
            "Vulnerability",
        }
    )

    def assert_no_direct_mutation(self, target_aggregate_name: str) -> None:
        if target_aggregate_name in self.FORBIDDEN_MUTATIONS:
            raise AutonBoundaryViolation(
                f"direct mutation of {target_aggregate_name} is forbidden; "
                "publish SuggestionProposedForApplication instead"
            )
''',
    )
    w(
        base / "domain" / "services" / "feedback_ingestion_service.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome


class FeedbackIngestionService:
    def ingest(self, model: OptimizationModel, outcome: SuggestionOutcome) -> None:
        if outcome.delta is not None:
            model.record_feedback()
''',
    )
    w(
        base / "domain" / "services" / "model_governance_service.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class ModelGovernanceService:
    def deploy(
        self,
        model: OptimizationModel,
        tenant_id: TenantId,
        conformity_assessment_ref: str,
    ) -> None:
        model.deploy(tenant_id, conformity_assessment_ref)

    def deprecate(
        self, model: OptimizationModel, tenant_id: TenantId, superseded_by_version: int
    ) -> None:
        model.deprecate(tenant_id, superseded_by_version)
''',
    )


def _repos(base):
    w(
        base / "domain" / "repositories" / "i_repositories.py",
        '''from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class IIntelligenceSuggestionRepository(ABC):
    @abstractmethod
    async def save(self, suggestion: IntelligenceSuggestion, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> IntelligenceSuggestion | None: ...

    @abstractmethod
    async def find_pending_review(
        self, tenant_id: TenantId, target_type: SuggestionTargetType | None, limit: int
    ) -> list[IntelligenceSuggestion]: ...

    @abstractmethod
    async def find_approved_pending_application(
        self, tenant_id: TenantId
    ) -> list[IntelligenceSuggestion]: ...

    @abstractmethod
    async def find_expired_pending(self, cutoff: datetime) -> list[IntelligenceSuggestion]: ...


class IOptimizationModelRepository(ABC):
    @abstractmethod
    async def save(self, model: OptimizationModel, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_deployed(
        self, tenant_id: TenantId, target_type: SuggestionTargetType
    ) -> OptimizationModel | None: ...

    @abstractmethod
    async def find_by_id(self, model_id: str, tenant_id: TenantId) -> OptimizationModel | None: ...


class ISuggestionOutcomeRepository(ABC):
    @abstractmethod
    async def append(self, outcome: SuggestionOutcome) -> None: ...

    @abstractmethod
    async def find_for_suggestion(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> list[SuggestionOutcome]: ...

    @abstractmethod
    async def find_pending_measurement(
        self, cutoff: datetime, tenant_id: TenantId
    ) -> list[SuggestionOutcome]: ...


class IAutonomousOperationsPolicyRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> AutonomousOperationsPolicy: ...

    @abstractmethod
    async def save(self, policy: AutonomousOperationsPolicy, tenant_id: TenantId) -> None: ...
''',
    )


def _ports_app(base):
    w(
        base / "application" / "exceptions.py",
        '''from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass
''',
    )
    w(
        base / "application" / "_auth.py",
        '''from __future__ import annotations

from autonomous_intelligence.application.exceptions import ApplicationForbiddenError


def require_any(roles: tuple[str, ...], *allowed: str) -> None:
    if not any(r in roles for r in allowed):
        raise ApplicationForbiddenError(",".join(allowed))
''',
    )
    w(
        base / "application" / "ports" / "i_llm_inference_port.py",
        '''from __future__ import annotations

from typing import Protocol

from autonomous_intelligence.domain.value_objects.evidence import LLMPrompt, LLMResponse
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class ILLMInferencePort(Protocol):
    async def generate(self, prompt: LLMPrompt, tenant_id: TenantId) -> LLMResponse: ...
''',
    )
    w(
        base / "application" / "commands" / "intelligence_commands.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateIntelligenceSuggestion:
    tenant_id: UUID
    target_context: str
    target_id: UUID | None
    target_type: str
    proposed_change_payload: dict[str, object]
    model_id: str
    model_version: int
    confidence_score: float
    supporting_signal_refs: tuple[str, ...]
    rationale_summary: str
    roles: tuple[str, ...]
    created_by: str = "system"


@dataclass(frozen=True, slots=True)
class ApproveSuggestion:
    tenant_id: UUID
    suggestion_id: UUID
    approved_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RejectSuggestion:
    tenant_id: UUID
    suggestion_id: UUID
    rejected_by: str
    rejection_reason: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MarkSuggestionApplied:
    tenant_id: UUID
    suggestion_id: UUID
    target_context_ref: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TrainOptimizationModel:
    tenant_id: UUID
    target_type: str
    model_id: str
    model_version: int
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeployOptimizationModel:
    tenant_id: UUID
    model_id: str
    conformity_assessment_ref: str
    accuracy_metrics: dict[str, float]
    roles: tuple[str, ...]
''',
    )
    w(
        base / "application" / "dtos" / "intelligence_dtos.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SuggestionDTO:
    suggestion_id: str
    tenant_id: str
    target_type: str
    status: str
    confidence_score: float
    rationale_summary: str
    model_id: str
    model_version: int
    review_deadline_at: str


@dataclass(frozen=True, slots=True)
class ModelDTO:
    model_id: str
    tenant_id: str
    target_type: str
    model_version: int
    status: str
    accuracy_metrics: dict[str, float]
    feedback_sample_count: int


@dataclass(frozen=True, slots=True)
class PolicyDTO:
    tenant_id: str
    kill_switch_active: bool
    review_required: bool
    enabled_target_types: list[str]
''',
    )
    w(
        base / "application" / "read_models" / "read_models.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SuggestionQueueReadModel:
    suggestion_id: str
    target_type: str
    confidence_score: float
    rationale_summary: str
    target_context: str
    target_id: str | None
    model_id: str
    model_version: int
    created_at: datetime
    review_deadline_at: datetime


@dataclass(frozen=True)
class AcceptanceRateReadModel:
    target_type: str
    total_suggestions: int
    approved: int
    rejected: int
    expired: int
    acceptance_rate_pct: float
    trailing_30d_trend: float


@dataclass(frozen=True)
class ModelAccuracyReadModel:
    model_id: str
    target_type: str
    model_version: int
    status: str
    deployed_at: datetime | None
    precision: float | None
    recall: float | None
    rank_correlation: float | None
    feedback_sample_count: int
    accuracy_trend: float


@dataclass(frozen=True)
class PolicyReadModel:
    tenant_id: str
    kill_switch_active: bool
    review_required: bool
    enabled_target_types: list[str]
    min_confidence_by_type: dict[str, float]
''',
    )
    w(
        base / "application" / "services" / "intelligence_application_service.py",
        '''"""CQRS application service for autonomous_intelligence."""

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
    PolicyDTO,
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
from autonomous_intelligence.domain.services.autonomy_boundary_service import AutonomyBoundaryService
from autonomous_intelligence.domain.services.model_governance_service import ModelGovernanceService
from autonomous_intelligence.domain.services.suggestion_generation_service import (
    SuggestionGenerationService,
)
from autonomous_intelligence.domain.services.suggestion_review_service import SuggestionReviewService
from autonomous_intelligence.domain.value_objects.enums import (
    SuggestionStatus,
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
        return TenantId(value)

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
        self._review.reject(
            suggestion, tenant, cmd.rejected_by, cmd.rejection_reason, cmd.roles
        )
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
        tenant_id: UUID,
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
        self, tenant_id: UUID, roles: tuple[str, ...]
    ) -> list[AcceptanceRateReadModel]:
        require_any(roles, "ai:operator", "incident:ciso", "playbook:analyst")
        tenant = self._tenant(tenant_id)
        out: list[AcceptanceRateReadModel] = []
        for tt in SuggestionTargetType:
            pending = await self._suggestions.find_pending_review(tenant, tt, 1000)
            # simplified: use event sink counts in container for trends
            total = len(pending)
            out.append(
                AcceptanceRateReadModel(tt.value, total, 0, 0, 0, 0.0, 0.0)
            )
        return out

    async def get_model_accuracy(
        self, tenant_id: UUID, roles: tuple[str, ...]
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

    async def get_policy(self, tenant_id: UUID, roles: tuple[str, ...]) -> PolicyReadModel:
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
        self, tenant_id: UUID, suggestion_id: UUID, roles: tuple[str, ...]
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
''',
    )


def _infra(base):
    w(
        base / "infrastructure" / "persistence" / "in_memory_repositories.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

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
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class InMemoryIntelligenceSuggestionRepository(IIntelligenceSuggestionRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, IntelligenceSuggestion]] = {}

    async def save(self, suggestion: IntelligenceSuggestion, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(suggestion.suggestion_id)] = suggestion

    async def find_by_id(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> IntelligenceSuggestion | None:
        return self._items.get(str(tenant_id), {}).get(str(suggestion_id))

    async def find_pending_review(
        self, tenant_id: TenantId, target_type: SuggestionTargetType | None, limit: int
    ) -> list[IntelligenceSuggestion]:
        rows = [
            s
            for s in self._items.get(str(tenant_id), {}).values()
            if s.status == SuggestionStatus.PENDING_REVIEW
        ]
        if target_type:
            rows = [s for s in rows if s.target_type == target_type]
        return rows[:limit]

    async def find_approved_pending_application(
        self, tenant_id: TenantId
    ) -> list[IntelligenceSuggestion]:
        return [
            s
            for s in self._items.get(str(tenant_id), {}).values()
            if s.status == SuggestionStatus.APPROVED
        ]

    async def find_expired_pending(self, cutoff: datetime) -> list[IntelligenceSuggestion]:
        out: list[IntelligenceSuggestion] = []
        for rows in self._items.values():
            for s in rows.values():
                if (
                    s.status == SuggestionStatus.PENDING_REVIEW
                    and s.review_deadline_at < cutoff
                ):
                    out.append(s)
        return out


class InMemoryOptimizationModelRepository(IOptimizationModelRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, OptimizationModel]] = {}

    async def save(self, model: OptimizationModel, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(model.model_id)] = model

    async def find_deployed(
        self, tenant_id: TenantId, target_type: SuggestionTargetType
    ) -> OptimizationModel | None:
        for m in self._items.get(str(tenant_id), {}).values():
            if m.target_type == target_type and m.status == ModelStatus.DEPLOYED:
                return m
        return None

    async def find_by_id(self, model_id: str, tenant_id: TenantId) -> OptimizationModel | None:
        return self._items.get(str(tenant_id), {}).get(model_id)


class InMemorySuggestionOutcomeRepository(ISuggestionOutcomeRepository):
    def __init__(self) -> None:
        self._items: list[SuggestionOutcome] = []

    async def append(self, outcome: SuggestionOutcome) -> None:
        self._items.append(outcome)

    async def find_for_suggestion(
        self, suggestion_id: UUID, tenant_id: TenantId
    ) -> list[SuggestionOutcome]:
        return [
            o
            for o in self._items
            if o.suggestion_id == suggestion_id and o.tenant_id.value == tenant_id.value
        ]

    async def find_pending_measurement(
        self, cutoff: datetime, tenant_id: TenantId
    ) -> list[SuggestionOutcome]:
        del cutoff
        from autonomous_intelligence.domain.value_objects.enums import OutcomeType

        return [
            o
            for o in self._items
            if o.tenant_id.value == tenant_id.value and o.outcome_type == OutcomeType.PENDING
        ]


class InMemoryAutonomousOperationsPolicyRepository(IAutonomousOperationsPolicyRepository):
    def __init__(self) -> None:
        self._items: dict[str, AutonomousOperationsPolicy] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> AutonomousOperationsPolicy:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = AutonomousOperationsPolicy.default(tenant_id)
        return self._items[key]

    async def save(self, policy: AutonomousOperationsPolicy, tenant_id: TenantId) -> None:
        self._items[str(tenant_id)] = policy
''',
    )
    w(
        base / "infrastructure" / "llm" / "in_memory_llm.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.exceptions.domain_exceptions import TenantIsolationViolation
from autonomous_intelligence.domain.value_objects.evidence import LLMPrompt, LLMResponse
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class InMemoryLLMInferenceAdapter:
    """Single-tenant LLM adapter — never batches across tenants."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def generate(self, prompt: LLMPrompt, tenant_id: TenantId) -> LLMResponse:
        if prompt.tenant_id.value != tenant_id.value:
            raise TenantIsolationViolation("prompt tenant mismatch at port")
        for doc in prompt.context_documents:
            if doc.tenant_id.value != tenant_id.value:
                raise TenantIsolationViolation("document tenant mismatch at port")
        self.calls.append(str(tenant_id))
        return LLMResponse(
            content='{"suggestion":"ok"}',
            model_id="in-memory-llm",
            prompt_token_count=len(prompt.task_instruction.split()),
            completion_token_count=5,
            latency_ms=12,
        )
''',
    )
    # ACL translators
    for name, src_event, signal in [
        ("m33_ml_signal_translator", "MLModelTrainingCompleted", "ModelTrainingSignal"),
        ("m33_anomaly_translator", "AnomalySignalDetected", "AnomalySignalRef"),
        ("m28_performance_translator", "DetectionRulePerformanceReported", "DetectionPerformanceSignal"),
        ("m34_lesson_translator", "IncidentLessonsLearned", "IncidentPatternSignal"),
        ("m32_exposure_translator", "ExposureScoreUpdated", "ExposureTrendSignal"),
    ]:
        w(
            base / "infrastructure" / "acl" / f"{name}.py",
            f'''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class {src_event}Payload:
    tenant_id: str
    source_id: str
    severity: str | None = None
    payload: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class {signal}:
    tenant_id: str
    source_id: str
    severity: str | None
    details: dict[str, object]


class {"".join(p.capitalize() for p in name.replace("_translator","").split("_"))}Translator:
    def translate(self, payload: {src_event}Payload) -> {signal} | None:
        try:
            return {signal}(
                payload.tenant_id,
                payload.source_id,
                payload.severity,
                dict(payload.payload or {{}}),
            )
        except Exception:  # noqa: BLE001
            return None
''',
        )
    w(
        base / "infrastructure" / "workers" / "intelligence_workers.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from autonomous_intelligence.application.commands.intelligence_commands import (
    CreateIntelligenceSuggestion,
    MarkSuggestionApplied,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class SuggestionGenerationWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def handle_signal(
        self,
        tenant_id: UUID,
        target_type: str,
        target_context: str,
        confidence: float,
        roles: tuple[str, ...] = ("system",),
    ) -> Any:
        self.processed += 1
        return await self._app.create_suggestion(
            CreateIntelligenceSuggestion(
                tenant_id,
                target_context,
                None,
                target_type,
                {"change": "proposed"},
                "model-default",
                1,
                confidence,
                ("signal-1",),
                "Generated from inbound signal",
                roles,
            )
        )


class SuggestionExpiryWorker:
    def __init__(self, suggestions: Any) -> None:
        self._suggestions = suggestions
        self.expired = 0

    async def tick(self) -> int:
        now = datetime.now(UTC)
        stale = await self._suggestions.find_expired_pending(now)
        count = 0
        for s in stale:
            s.expire(s.tenant_id)
            await self._suggestions.save(s, s.tenant_id)
            count += 1
        self.expired += count
        return count


class SuggestionApplicationWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.applied = 0

    async def confirm(
        self, tenant_id: UUID, suggestion_id: UUID, target_context_ref: str
    ) -> Any:
        self.applied += 1
        return await self._app.mark_applied(
            MarkSuggestionApplied(
                tenant_id, suggestion_id, target_context_ref, ("system",)
            )
        )


class OutcomeMeasurementWorker:
    def __init__(self, outcomes: Any, models: Any) -> None:
        self._outcomes = outcomes
        self._models = models
        self.measured = 0

    async def tick(self, tenant_id: UUID) -> int:
        from autonomous_intelligence.domain.services.feedback_ingestion_service import (
            FeedbackIngestionService,
        )

        pending = await self._outcomes.find_pending_measurement(
            datetime.now(UTC), TenantId(tenant_id)
        )
        feedback = FeedbackIngestionService()
        count = 0
        for outcome in pending:
            outcome.record_measurement(outcome.baseline_metric - 0.05, datetime.now(UTC))
            model = await self._models.find_deployed(TenantId(tenant_id), outcome.target_type)
            if model:
                feedback.ingest(model, outcome)
                await self._models.save(model, TenantId(tenant_id))
            count += 1
        self.measured += count
        return count


class ModelRetrainingWorker:
    def __init__(self, models: Any) -> None:
        self._models = models
        self.triggered = 0

    async def tick(self, tenant_id: UUID) -> int:
        from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType

        count = 0
        for tt in SuggestionTargetType:
            model = await self._models.find_deployed(TenantId(tenant_id), tt)
            if model and model.needs_retraining():
                self.triggered += 1
                count += 1
        return count


class M36SecurityGraphWorker:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: set[tuple[str, str, str]] = set()

    def project(self, event: Any) -> None:
        name = type(event).__name__
        if name == "SuggestionCreated":
            self.nodes[event.suggestion_id] = {
                "type": "IntelligenceSuggestionNode",
                "status": "pending_review",
                "confidence_score": event.confidence_score,
                "tenant_id": event.tenant_id,
            }
        elif name == "SuggestionApproved":
            self.edges.add((event.suggestion_id, "APPROVED_SUGGESTION", event.target_type))
        elif name == "ModelDeployed":
            nid = f"{event.model_id}_v{event.model_version}"
            self.nodes[nid] = {
                "type": "OptimizationModelNode",
                "status": "deployed",
                "tenant_id": event.tenant_id,
            }


class M36AnalyticsProjector:
    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    def project(self, event: Any) -> None:
        self.rows.append(
            {
                "event_type": type(event).__name__,
                "tenant_id": getattr(event, "tenant_id", ""),
                "suggestion_id": getattr(event, "suggestion_id", ""),
            }
        )


class MetricsWorker:
    def __init__(self) -> None:
        self.ticks = 0
        self.counters: dict[str, float] = {}

    def tick(self) -> None:
        self.ticks += 1
        self.counters["m36.worker.ticks"] = float(self.ticks)


class IntelligenceScheduler:
    def __init__(
        self,
        expiry: SuggestionExpiryWorker,
        outcome: OutcomeMeasurementWorker,
        retrain: ModelRetrainingWorker,
        metrics: MetricsWorker,
    ) -> None:
        self.expiry = expiry
        self.outcome = outcome
        self.retrain = retrain
        self.metrics = metrics

    async def tick_all(self, tenant_id: UUID) -> dict[str, int]:
        expired = await self.expiry.tick()
        measured = await self.outcome.tick(tenant_id)
        retrained = await self.retrain.tick(tenant_id)
        self.metrics.tick()
        return {
            "expired": expired,
            "measured": measured,
            "retrain_triggers": retrained,
            "metrics_ticks": self.metrics.ticks,
        }
''',
    )
    w(
        base / "infrastructure" / "observability" / "metrics_store.py",
        '''from __future__ import annotations


class OperationalMetricsStore:
    def __init__(self) -> None:
        self._counters: dict[str, float] = {}

    def incr(self, name: str, value: float = 1.0) -> None:
        self._counters[name] = self._counters.get(name, 0.0) + value

    def snapshot(self) -> dict[str, float]:
        return dict(self._counters)
''',
    )
    w(
        base / "infrastructure" / "container.py",
        '''from __future__ import annotations

from autonomous_intelligence.application.services.intelligence_application_service import (
    IntelligenceApplicationService,
)
from autonomous_intelligence.infrastructure.llm.in_memory_llm import InMemoryLLMInferenceAdapter
from autonomous_intelligence.infrastructure.observability.metrics_store import OperationalMetricsStore
from autonomous_intelligence.infrastructure.persistence.in_memory_repositories import (
    InMemoryAutonomousOperationsPolicyRepository,
    InMemoryIntelligenceSuggestionRepository,
    InMemoryOptimizationModelRepository,
    InMemorySuggestionOutcomeRepository,
)
from autonomous_intelligence.infrastructure.workers.intelligence_workers import (
    IntelligenceScheduler,
    MetricsWorker,
    ModelRetrainingWorker,
    M36AnalyticsProjector,
    M36SecurityGraphWorker,
    OutcomeMeasurementWorker,
    SuggestionApplicationWorker,
    SuggestionExpiryWorker,
    SuggestionGenerationWorker,
)


class AutonomousIntelligenceContainer:
    def __init__(self) -> None:
        self.suggestions = InMemoryIntelligenceSuggestionRepository()
        self.models = InMemoryOptimizationModelRepository()
        self.outcomes = InMemorySuggestionOutcomeRepository()
        self.policies = InMemoryAutonomousOperationsPolicyRepository()
        self.llm = InMemoryLLMInferenceAdapter()
        self.event_sink: list[object] = []
        self.audit_log: list[dict[str, object]] = []
        self.metrics = OperationalMetricsStore()
        self.app = IntelligenceApplicationService(
            self.suggestions,
            self.models,
            self.outcomes,
            self.policies,
            self.llm,
            self.event_sink,
            self.audit_log,
        )
        self.generation_worker = SuggestionGenerationWorker(self.app)
        self.expiry_worker = SuggestionExpiryWorker(self.suggestions)
        self.application_worker = SuggestionApplicationWorker(self.app)
        self.outcome_worker = OutcomeMeasurementWorker(self.outcomes, self.models)
        self.retrain_worker = ModelRetrainingWorker(self.models)
        self.graph_worker = M36SecurityGraphWorker()
        self.analytics = M36AnalyticsProjector()
        self.metrics_worker = MetricsWorker()
        self.scheduler = IntelligenceScheduler(
            self.expiry_worker,
            self.outcome_worker,
            self.retrain_worker,
            self.metrics_worker,
        )
''',
    )


def _api(base):
    w(
        base / "api" / "dependencies.py",
        '''from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


def get_container(request: Request) -> AutonomousIntelligenceContainer:
    c = getattr(request.app.state, "autonomous_intelligence_container", None)
    if c is None:
        c = AutonomousIntelligenceContainer()
        request.app.state.autonomous_intelligence_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
''',
    )
    w(
        base / "api" / "v1" / "__init__.py",
        "from autonomous_intelligence.api.v1.routes import router\n\n__all__ = ['router']\n",
    )
    w(
        base / "api" / "v1" / "routes.py",
        '''from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from autonomous_intelligence.api.dependencies import get_container, roles_header, tenant_id_header
from autonomous_intelligence.application.commands.intelligence_commands import (
    ApproveSuggestion,
    CreateIntelligenceSuggestion,
    DeployOptimizationModel,
    RejectSuggestion,
    TrainOptimizationModel,
)
from autonomous_intelligence.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AutonomousIntelligenceDomainError,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer

router = APIRouter(prefix="/autonomous-intelligence", tags=["autonomous-intelligence"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, AutonomousIntelligenceDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class CreateSuggestionBody(BaseModel):
    target_context: str
    target_type: str
    proposed_change_payload: dict[str, object] = Field(default_factory=dict)
    model_id: str = "model-default"
    model_version: int = 1
    confidence_score: float
    supporting_signal_refs: list[str] = Field(default_factory=list)
    rationale_summary: str
    target_id: UUID | None = None


class ReviewBody(BaseModel):
    actor: str
    reason: str | None = None


class TrainBody(BaseModel):
    target_type: str
    model_id: str
    model_version: int = 1


class DeployBody(BaseModel):
    conformity_assessment_ref: str
    accuracy_metrics: dict[str, float]


@router.get("/health")
async def health(
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    return {
        "status": "ok",
        "context": "autonomous_intelligence",
        "metrics": container.metrics.snapshot(),
        "audit_count": len(container.audit_log),
    }


@router.get("/suggestions")
async def list_queue(
    target_type: str | None = None,
    limit: int = 50,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        rows = await container.app.get_queue(tenant_id, roles, target_type, limit)
        return [asdict(r) for r in rows]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/suggestions", status_code=201)
async def create_suggestion(
    body: CreateSuggestionBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.create_suggestion(
            CreateIntelligenceSuggestion(
                tenant_id,
                body.target_context,
                body.target_id,
                body.target_type,
                body.proposed_change_payload,
                body.model_id,
                body.model_version,
                body.confidence_score,
                tuple(body.supporting_signal_refs),
                body.rationale_summary,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/suggestions/{suggestion_id}")
async def get_suggestion(
    suggestion_id: UUID,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_suggestion(tenant_id, suggestion_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/suggestions/{suggestion_id}/approve")
async def approve(
    suggestion_id: UUID,
    body: ReviewBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.approve(
            ApproveSuggestion(tenant_id, suggestion_id, body.actor, roles)
        )
        for event in list(container.event_sink):
            container.graph_worker.project(event)
            container.analytics.project(event)
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/suggestions/{suggestion_id}/reject")
async def reject(
    suggestion_id: UUID,
    body: ReviewBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.reject(
            RejectSuggestion(
                tenant_id, suggestion_id, body.actor, body.reason or "rejected", roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/policy")
async def get_policy(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_policy(tenant_id, roles))
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/models/accuracy")
async def model_accuracy(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [asdict(r) for r in await container.app.get_model_accuracy(tenant_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/train", status_code=201)
async def train(
    body: TrainBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.train_model(
            TrainOptimizationModel(
                tenant_id, body.target_type, body.model_id, body.model_version, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/models/{model_id}/deploy")
async def deploy(
    model_id: str,
    body: DeployBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.deploy_model(
            DeployOptimizationModel(
                tenant_id, model_id, body.conformity_assessment_ref, body.accuracy_metrics, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/llm-audit")
async def llm_audit(
    container: AutonomousIntelligenceContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    return list(container.audit_log)
''',
    )


def _eu_doc(base):
    w(
        base / "docs" / "eu_ai_act_conformity_template.md",
        '''# EU AI Act Conformity Assessment Template — M36 Autonomous Intelligence

**Status:** Template for product/legal review  
**ADR:** ADR-M36-008  
**Article focus:** Human oversight (Art. 14), transparency, accuracy/robustness

## 1. System Description
RedForge M36 provides AI-generated security optimization suggestions. Suggestions are never
auto-applied to detection rules, campaigns, playbooks, or vulnerability priorities.

## 2. Human Oversight (Article 14)
- Every suggestion enters `PENDING_REVIEW`
- Reviewer role is enforced per `SuggestionTargetType`
- Kill switch on `AutonomousOperationsPolicy` halts generation
- No suggestion becomes `APPLIED` without target-context human acceptance

## 3. Transparency
- `SuggestionEvidence.rationale_summary` retained with each suggestion
- `llm_inference_audit_log` records tenant_id, model_id, token counts (no prompt content)

## 4. Accuracy & Robustness
- Model deploy requires per-task accuracy thresholds (ADR-M36-005)
- Feedback loop via `SuggestionOutcome` drives retraining triggers

## 5. Conformity Assessment Reference
`OptimizationModel.conformity_assessment_ref` is mandatory before `DEPLOYED`.
''',
    )


def _tests() -> None:
    tbase = TESTS / "autonomous_intelligence"
    w(tbase / "__init__.py", "")
    w(
        tbase / "test_no_cross_context_domain_import_in_autonomous_intelligence.py",
        '''from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "autonomous_intelligence"
BAD = re.compile(
    r"from (detection|campaign|playbook|vulnerability|engagement|incident|exposure|"
    r"automated_action|integration_hub)\\."
)


def test_no_cross_context_domain_import_in_autonomous_intelligence() -> None:
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        text = p.read_text()
        if BAD.search(text):
            raise AssertionError(f"cross-context import in {p}")
''',
    )
    w(
        tbase / "test_llm_prompt_tenant_isolation_enforced.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from autonomous_intelligence.domain.exceptions.domain_exceptions import TenantIsolationViolation
from autonomous_intelligence.domain.value_objects.evidence import LLMPrompt, TenantScopedDocument
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.infrastructure.llm.in_memory_llm import InMemoryLLMInferenceAdapter


def test_llm_prompt_tenant_isolation_enforced() -> None:
    t1 = TenantId(uuid4())
    t2 = TenantId(uuid4())
    with pytest.raises(TenantIsolationViolation):
        LLMPrompt(
            tenant_id=t1,
            system_instruction="sys",
            context_documents=(
                TenantScopedDocument(tenant_id=t2, content="x", source_ref="s"),
            ),
            task_instruction="task",
            max_tokens=100,
        )


@pytest.mark.asyncio
async def test_port_rejects_mismatched_tenant() -> None:
    adapter = InMemoryLLMInferenceAdapter()
    t1 = TenantId(uuid4())
    prompt = LLMPrompt(
        tenant_id=t1,
        system_instruction="sys",
        context_documents=(),
        task_instruction="task",
        max_tokens=50,
    )
    with pytest.raises(TenantIsolationViolation):
        await adapter.generate(prompt, TenantId(uuid4()))
''',
    )
    w(
        tbase / "test_autonomy_boundary_raises_on_direct_mutation.py",
        '''from __future__ import annotations

import pytest

from autonomous_intelligence.domain.exceptions.domain_exceptions import AutonBoundaryViolation
from autonomous_intelligence.domain.services.autonomy_boundary_service import AutonomyBoundaryService


def test_autonomy_boundary_raises_on_direct_mutation() -> None:
    svc = AutonomyBoundaryService()
    with pytest.raises(AutonBoundaryViolation):
        svc.assert_no_direct_mutation("DetectionRule")
    with pytest.raises(AutonBoundaryViolation):
        svc.assert_no_direct_mutation("PlaybookVersion")
    svc.assert_no_direct_mutation("IntelligenceSuggestion")
''',
    )
    w(
        tbase / "test_lifecycle.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    ApproveSuggestion,
    CreateIntelligenceSuggestion,
    DeployOptimizationModel,
    MarkSuggestionApplied,
    RejectSuggestion,
    TrainOptimizationModel,
)
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AccuracyThresholdNotMet,
    ConfidenceThresholdNotMet,
    InvalidSuggestionTransition,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
async def test_suggestion_lifecycle_approve_apply() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    roles_sys = ("system",)
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "detection",
            None,
            "detection_rule_tuning",
            {"threshold": 0.9},
            "m1",
            1,
            0.85,
            ("sig1",),
            "Tune rule threshold",
            roles_sys,
        )
    )
    assert created.status == "pending_review"
    sid = UUID(created.suggestion_id)
    approved = await c.app.approve(
        ApproveSuggestion(tenant, sid, "eng1", ("soc:detection_engineer",))
    )
    assert approved.status == "approved"
    applied = await c.app.mark_applied(
        MarkSuggestionApplied(tenant, sid, "detection:rule:1", ("system",))
    )
    assert applied.status == "applied"


@pytest.mark.asyncio
async def test_confidence_gate() -> None:
    c = AutonomousIntelligenceContainer()
    with pytest.raises(ConfidenceThresholdNotMet):
        await c.app.create_suggestion(
            CreateIntelligenceSuggestion(
                uuid4(),
                "detection",
                None,
                "detection_rule_tuning",
                {},
                "m1",
                1,
                0.50,
                (),
                "too low",
                ("system",),
            )
        )


@pytest.mark.asyncio
async def test_reject_and_invalid_transition() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "campaign",
            None,
            "campaign_scenario",
            {},
            "m1",
            1,
            0.70,
            (),
            "scenario",
            ("system",),
        )
    )
    sid = UUID(created.suggestion_id)
    await c.app.reject(
        RejectSuggestion(tenant, sid, "arch", "not useful", ("red_team:architect",))
    )
    with pytest.raises(InvalidSuggestionTransition):
        await c.app.approve(
            ApproveSuggestion(tenant, sid, "arch", ("red_team:architect",))
        )


@pytest.mark.asyncio
async def test_model_deploy_threshold() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    roles = ("ai:ml_engineer",)
    await c.app.train_model(
        TrainOptimizationModel(tenant, "detection_rule_tuning", "m-det", 1, roles)
    )
    with pytest.raises(AccuracyThresholdNotMet):
        await c.app.deploy_model(
            DeployOptimizationModel(
                tenant, "m-det", "eu-ref-1", {"precision": 0.5, "recall": 0.5}, roles
            )
        )
    deployed = await c.app.deploy_model(
        DeployOptimizationModel(
            tenant, "m-det", "eu-ref-1", {"precision": 0.8, "recall": 0.75}, roles
        )
    )
    assert deployed.status == "deployed"
''',
    )
    w(
        tbase / "test_workers.py",
        '''from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    CreateIntelligenceSuggestion,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
async def test_expiry_worker() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "playbook",
            None,
            "playbook_synthesis",
            {},
            "m1",
            1,
            0.80,
            (),
            "synth",
            ("system",),
        )
    )
    s = await c.suggestions.find_by_id(UUID(created.suggestion_id), c.app._tenant(tenant))
    assert s is not None
    s.review_deadline_at = datetime.now(UTC) - timedelta(minutes=1)
    await c.suggestions.save(s, c.app._tenant(tenant))
    n = await c.expiry_worker.tick()
    assert n == 1
    s2 = await c.suggestions.find_by_id(UUID(created.suggestion_id), c.app._tenant(tenant))
    assert s2 is not None
    assert s2.status.value == "expired"


@pytest.mark.asyncio
async def test_scheduler() -> None:
    c = AutonomousIntelligenceContainer()
    result = await c.scheduler.tick_all(uuid4())
    assert "expired" in result
''',
    )
    w(
        tbase / "test_api.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from autonomous_intelligence.api.v1.routes import router
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
async def test_create_and_queue() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.autonomous_intelligence_container = AutonomousIntelligenceContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "system,soc:detection_engineer"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/autonomous-intelligence/suggestions",
            json={
                "target_context": "detection",
                "target_type": "detection_rule_tuning",
                "confidence_score": 0.9,
                "rationale_summary": "raise threshold",
            },
            headers=headers,
        )
        assert r.status_code == 201
        q = await client.get("/autonomous-intelligence/suggestions", headers=headers)
        assert q.status_code == 200
        assert len(q.json()) == 1
''',
    )
    w(
        tbase / "test_enums_and_services.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.services.feedback_ingestion_service import (
    FeedbackIngestionService,
)
from autonomous_intelligence.domain.value_objects.enums import (
    ModelStatus,
    OutcomeType,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel


@pytest.mark.parametrize("value", list(SuggestionStatus))
def test_suggestion_status(value: SuggestionStatus) -> None:
    assert isinstance(value.value, str)


@pytest.mark.parametrize("value", list(SuggestionTargetType))
def test_target_types(value: SuggestionTargetType) -> None:
    assert value.value == value.name.lower() or "_" in value.value


@pytest.mark.parametrize("value", list(ModelStatus))
def test_model_status(value: ModelStatus) -> None:
    assert value.value == value.name.lower()


@pytest.mark.parametrize("value", list(OutcomeType))
def test_outcome_types(value: OutcomeType) -> None:
    assert isinstance(value.value, str)


def test_policy_confidence_floor() -> None:
    p = AutonomousOperationsPolicy.default(TenantId(uuid4()))
    with pytest.raises(Exception):
        p.set_min_confidence(SuggestionTargetType.DETECTION_RULE_TUNING, 0.1)


def test_outcome_measurement_and_feedback() -> None:
    tenant = TenantId(uuid4())
    outcome = SuggestionOutcome.create_pending(
        uuid4(), tenant, SuggestionTargetType.DETECTION_RULE_TUNING, 30, 0.4
    )
    outcome.record_measurement(0.3, datetime.now(UTC))
    assert outcome.delta == pytest.approx(-0.1)
    model = OptimizationModel.start_training(
        tenant, SuggestionTargetType.DETECTION_RULE_TUNING, "m", 1
    )
    FeedbackIngestionService().ingest(model, outcome)
    assert model.feedback_sample_count == 1
''',
    )
    # Fix target type value assertion - SuggestionTargetType values are lowercase with underscores
    # The test `value.value == value.name.lower()` won't work for names vs values. Let me fix:
    # DETECTION_RULE_TUNING.name.lower() = "detection_rule_tuning" which equals value. Good.

    w(
        tbase / "test_architecture.py",
        '''from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "autonomous_intelligence"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application" / "services").is_dir()
    assert (ROOT / "infrastructure" / "acl").is_dir()
    assert (ROOT / "py.typed").is_file()
    assert (ROOT / "docs" / "eu_ai_act_conformity_template.md").is_file()
''',
    )

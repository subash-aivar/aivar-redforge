"""Generate autonomous_intelligence bounded context (M36 Phase 1 core)."""

from __future__ import annotations

from .common import SRC, TESTS, empty_inits, w


def write() -> None:
    base = SRC / "autonomous_intelligence"
    empty_inits(
        base,
        base / "domain",
        base / "domain" / "aggregates",
        base / "domain" / "events",
        base / "domain" / "exceptions",
        base / "domain" / "repositories",
        base / "domain" / "services",
        base / "domain" / "value_objects",
        base / "application",
        base / "application" / "commands",
        base / "application" / "dtos",
        base / "application" / "services",
        base / "application" / "ports",
        base / "application" / "read_models",
        base / "infrastructure",
        base / "infrastructure" / "persistence",
        base / "infrastructure" / "workers",
        base / "infrastructure" / "acl",
        base / "infrastructure" / "llm",
        base / "infrastructure" / "projectors",
        base / "infrastructure" / "observability",
        base / "api",
        base / "api" / "v1",
        base / "docs",
    )
    w(base / "__init__.py", '"""M36 autonomous_intelligence bounded context."""\n')
    w(base / "py.typed", "")
    _vos(base)
    _exceptions(base)
    _events(base)
    _aggregates(base)


def _vos(base):
    w(
        base / "domain" / "value_objects" / "enums.py",
        '''"""Frozen enums for autonomous_intelligence (M36)."""

from __future__ import annotations

from enum import StrEnum


class SuggestionStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


class SuggestionTargetType(StrEnum):
    DETECTION_RULE_TUNING = "detection_rule_tuning"
    CAMPAIGN_SCENARIO = "campaign_scenario"
    PLAYBOOK_SYNTHESIS = "playbook_synthesis"
    VULNERABILITY_PRIORITY_ADJUSTMENT = "vulnerability_priority_adjustment"


class ModelStatus(StrEnum):
    TRAINING = "training"
    VALIDATING = "validating"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"
    FAILED = "failed"


class OutcomeType(StrEnum):
    MEASURABLE = "measurable"
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"


class SuggestionPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SuggestionCategory(StrEnum):
    DETECTION = "detection"
    OFFENSIVE = "offensive"
    DEFENSIVE = "defensive"
    VULNERABILITY = "vulnerability"
''',
    )
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class SuggestionId:
    value: UUID

    @classmethod
    def generate(cls) -> SuggestionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ModelId:
    value: str

    def __str__(self) -> str:
        return self.value
''',
    )
    w(
        base / "domain" / "value_objects" / "evidence.py",
        '''"""SuggestionEvidence and related value objects — C4 / ADR-M36-003."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionEvidence:
    model_id: str
    model_version: int
    confidence_score: float
    supporting_signal_refs: tuple[str, ...]
    rationale_summary: str
    generated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence_score <= 1.0:
            raise DomainInvariantViolation("confidence_score must be in [0.0, 1.0]")
        if len(self.rationale_summary) > 2000:
            raise DomainInvariantViolation("rationale_summary max 2000 chars")


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionTargetRef:
    target_context: str
    target_id: UUID | None
    target_type: SuggestionTargetType
    proposed_change_payload: dict[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionProposal:
    suggestion_id: str
    tenant_id: str
    target_ref: SuggestionTargetRef
    proposal_payload: dict[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class TenantScopedDocument:
    tenant_id: TenantId
    content: str
    source_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class LLMPrompt:
    tenant_id: TenantId
    system_instruction: str
    context_documents: tuple[TenantScopedDocument, ...]
    task_instruction: str
    max_tokens: int

    def __post_init__(self) -> None:
        from autonomous_intelligence.domain.exceptions.domain_exceptions import (
            TenantIsolationViolation,
        )

        for doc in self.context_documents:
            if doc.tenant_id.value != self.tenant_id.value:
                raise TenantIsolationViolation(
                    "LLMPrompt context document tenant mismatch"
                )


@dataclass(frozen=True, slots=True, kw_only=True)
class LLMResponse:
    content: str
    model_id: str
    prompt_token_count: int
    completion_token_count: int
    latency_ms: int


@dataclass(frozen=True, slots=True, kw_only=True)
class PromptHash:
    value: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionConfidence:
    score: float
    threshold: float

    @property
    def meets_threshold(self) -> bool:
        return self.score >= self.threshold


DEFAULT_MIN_CONFIDENCE: dict[SuggestionTargetType, float] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: 0.75,
    SuggestionTargetType.CAMPAIGN_SCENARIO: 0.65,
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: 0.70,
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: 0.60,
}

CONFIDENCE_FLOORS: dict[SuggestionTargetType, float] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: 0.60,
    SuggestionTargetType.CAMPAIGN_SCENARIO: 0.55,
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: 0.60,
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: 0.50,
}

REVIEW_ROLES: dict[SuggestionTargetType, str] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: "soc:detection_engineer",
    SuggestionTargetType.CAMPAIGN_SCENARIO: "red_team:architect",
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: "soc:security_engineer",
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: "vuln:manager",
}
''',
    )


def _exceptions(base):
    w(
        base / "domain" / "exceptions" / "domain_exceptions.py",
        '''from __future__ import annotations


class AutonomousIntelligenceDomainError(Exception):
    pass


class DomainInvariantViolation(AutonomousIntelligenceDomainError):
    pass


class TenantMismatch(AutonomousIntelligenceDomainError):
    pass


class TenantIsolationViolation(AutonomousIntelligenceDomainError):
    pass


class AutonBoundaryViolation(AutonomousIntelligenceDomainError):
    pass


class InvalidSuggestionTransition(AutonomousIntelligenceDomainError):
    pass


class ConfidenceThresholdNotMet(AutonomousIntelligenceDomainError):
    pass


class AccuracyThresholdNotMet(AutonomousIntelligenceDomainError):
    pass


class AuthorizationDenied(AutonomousIntelligenceDomainError):
    pass


class InvalidModelTransition(AutonomousIntelligenceDomainError):
    pass
''',
    )


def _events(base):
    w(
        base / "domain" / "events" / "base.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseIntelligenceEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""
''',
    )
    w(
        base / "domain" / "events" / "intelligence_events.py",
        '''from __future__ import annotations

from dataclasses import dataclass

from autonomous_intelligence.domain.events.base import BaseIntelligenceEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionCreated(BaseIntelligenceEvent):
    suggestion_id: str
    target_type: str
    confidence_score: float
    model_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionApproved(BaseIntelligenceEvent):
    suggestion_id: str
    approved_by: str
    target_type: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionRejected(BaseIntelligenceEvent):
    suggestion_id: str
    rejected_by: str
    rejection_reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionProposedForApplication(BaseIntelligenceEvent):
    suggestion_id: str
    target_type: str
    target_context: str
    target_id: str | None
    proposal_payload: dict[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionApplied(BaseIntelligenceEvent):
    suggestion_id: str
    applied_at: str
    target_context_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionExpired(BaseIntelligenceEvent):
    suggestion_id: str
    expired_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionWithdrawn(BaseIntelligenceEvent):
    suggestion_id: str
    withdrawn_at: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionOutcomeCaptured(BaseIntelligenceEvent):
    suggestion_id: str
    delta: float | None
    horizon_days: int
    target_type: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelDeployed(BaseIntelligenceEvent):
    model_id: str
    target_type: str
    model_version: int
    accuracy_metrics: dict[str, float]


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelDeprecated(BaseIntelligenceEvent):
    model_id: str
    superseded_by_version: int
''',
    )


def _aggregates(base):
    w(
        base / "domain" / "aggregates" / "intelligence_suggestion.py",
        '''"""IntelligenceSuggestion aggregate — human-in-the-loop lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from autonomous_intelligence.domain.events.intelligence_events import (
    SuggestionApplied,
    SuggestionApproved,
    SuggestionCreated,
    SuggestionExpired,
    SuggestionProposedForApplication,
    SuggestionRejected,
    SuggestionWithdrawn,
)
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AuthorizationDenied,
    InvalidSuggestionTransition,
    TenantMismatch,
)
from autonomous_intelligence.domain.value_objects.enums import (
    SuggestionPriority,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    REVIEW_ROLES,
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import SuggestionId, TenantId


class IntelligenceSuggestion:
    __slots__ = (
        "_pending_events",
        "approved_by",
        "created_at",
        "evidence",
        "priority",
        "rejected_by",
        "rejection_reason",
        "review_deadline_at",
        "reviewed_at",
        "status",
        "suggestion_id",
        "target_ref",
        "tenant_id",
        "version",
    )

    def __init__(
        self,
        suggestion_id: SuggestionId,
        tenant_id: TenantId,
        target_ref: SuggestionTargetRef,
        evidence: SuggestionEvidence,
        status: SuggestionStatus,
        created_at: datetime,
        review_deadline_at: datetime,
        *,
        priority: SuggestionPriority = SuggestionPriority.MEDIUM,
        approved_by: str | None = None,
        rejected_by: str | None = None,
        rejection_reason: str | None = None,
        reviewed_at: datetime | None = None,
        version: int = 1,
    ) -> None:
        self.suggestion_id = suggestion_id
        self.tenant_id = tenant_id
        self.target_ref = target_ref
        self.evidence = evidence
        self.status = status
        self.created_at = created_at
        self.review_deadline_at = review_deadline_at
        self.priority = priority
        self.approved_by = approved_by
        self.rejected_by = rejected_by
        self.rejection_reason = rejection_reason
        self.reviewed_at = reviewed_at
        self.version = version
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: Any) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        target_ref: SuggestionTargetRef,
        evidence: SuggestionEvidence,
        *,
        review_ttl_hours: int = 72,
        priority: SuggestionPriority = SuggestionPriority.MEDIUM,
    ) -> IntelligenceSuggestion:
        now = datetime.now(UTC)
        suggestion = cls(
            SuggestionId.generate(),
            tenant_id,
            target_ref,
            evidence,
            SuggestionStatus.PENDING_REVIEW,
            now,
            now + timedelta(hours=review_ttl_hours),
            priority=priority,
        )
        suggestion._emit(
            SuggestionCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(suggestion.suggestion_id),
                suggestion_id=str(suggestion.suggestion_id),
                target_type=target_ref.target_type.value,
                confidence_score=evidence.confidence_score,
                model_id=evidence.model_id,
            )
        )
        return suggestion

    def approve(self, tenant_id: TenantId, approved_by: str, roles: tuple[str, ...]) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.PENDING_REVIEW:
            raise InvalidSuggestionTransition(f"cannot approve from {self.status.value}")
        required = REVIEW_ROLES[self.target_ref.target_type]
        if required not in roles:
            raise AuthorizationDenied(f"requires role {required}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.APPROVED
        self.approved_by = approved_by
        self.reviewed_at = now
        self.version += 1
        self._emit(
            SuggestionApproved(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                approved_by=approved_by,
                target_type=self.target_ref.target_type.value,
            )
        )
        self._emit(
            SuggestionProposedForApplication(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                target_type=self.target_ref.target_type.value,
                target_context=self.target_ref.target_context,
                target_id=str(self.target_ref.target_id) if self.target_ref.target_id else None,
                proposal_payload=dict(self.target_ref.proposed_change_payload),
            )
        )

    def reject(
        self, tenant_id: TenantId, rejected_by: str, reason: str, roles: tuple[str, ...]
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.PENDING_REVIEW:
            raise InvalidSuggestionTransition(f"cannot reject from {self.status.value}")
        required = REVIEW_ROLES[self.target_ref.target_type]
        if required not in roles:
            raise AuthorizationDenied(f"requires role {required}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.REJECTED
        self.rejected_by = rejected_by
        self.rejection_reason = reason
        self.reviewed_at = now
        self.version += 1
        self._emit(
            SuggestionRejected(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                rejected_by=rejected_by,
                rejection_reason=reason,
            )
        )

    def mark_applied(self, tenant_id: TenantId, target_context_ref: str) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.APPROVED:
            raise InvalidSuggestionTransition(f"cannot apply from {self.status.value}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.APPLIED
        self.version += 1
        self._emit(
            SuggestionApplied(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                applied_at=now.isoformat(),
                target_context_ref=target_context_ref,
            )
        )

    def expire(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.PENDING_REVIEW:
            raise InvalidSuggestionTransition(f"cannot expire from {self.status.value}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.EXPIRED
        self.version += 1
        self._emit(
            SuggestionExpired(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                expired_at=now.isoformat(),
            )
        )

    def withdraw(self, tenant_id: TenantId, reason: str) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in {SuggestionStatus.PENDING_REVIEW, SuggestionStatus.APPROVED}:
            raise InvalidSuggestionTransition(f"cannot withdraw from {self.status.value}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.WITHDRAWN
        self.version += 1
        self._emit(
            SuggestionWithdrawn(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                withdrawn_at=now.isoformat(),
                reason=reason,
            )
        )

    @property
    def target_type(self) -> SuggestionTargetType:
        return self.target_ref.target_type
''',
    )
    w(
        base / "domain" / "aggregates" / "optimization_model.py",
        '''"""OptimizationModel aggregate — ADR-M36-005."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from autonomous_intelligence.domain.events.intelligence_events import ModelDeprecated, ModelDeployed
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AccuracyThresholdNotMet,
    DomainInvariantViolation,
    InvalidModelTransition,
    TenantMismatch,
)
from autonomous_intelligence.domain.value_objects.enums import ModelStatus, SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import ModelId, TenantId

ACCURACY_THRESHOLDS: dict[SuggestionTargetType, dict[str, float]] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: {"precision": 0.75, "recall": 0.70},
    SuggestionTargetType.CAMPAIGN_SCENARIO: {"relevance_score": 0.65},
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: {"structure_score": 0.70},
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: {"rank_correlation": 0.60},
}


class OptimizationModel:
    __slots__ = (
        "_pending_events",
        "accuracy_metrics",
        "conformity_assessment_ref",
        "created_at",
        "deployed_at",
        "feedback_sample_count",
        "model_id",
        "model_version",
        "retraining_threshold",
        "status",
        "target_type",
        "tenant_id",
    )

    def __init__(
        self,
        model_id: ModelId,
        tenant_id: TenantId,
        target_type: SuggestionTargetType,
        model_version: int,
        status: ModelStatus,
        *,
        accuracy_metrics: dict[str, float] | None = None,
        conformity_assessment_ref: str | None = None,
        feedback_sample_count: int = 0,
        retraining_threshold: int = 50,
        created_at: datetime | None = None,
        deployed_at: datetime | None = None,
    ) -> None:
        self.model_id = model_id
        self.tenant_id = tenant_id
        self.target_type = target_type
        self.model_version = model_version
        self.status = status
        self.accuracy_metrics = dict(accuracy_metrics or {})
        self.conformity_assessment_ref = conformity_assessment_ref
        self.feedback_sample_count = feedback_sample_count
        self.retraining_threshold = retraining_threshold
        self.created_at = created_at or datetime.now(UTC)
        self.deployed_at = deployed_at
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def start_training(
        cls,
        tenant_id: TenantId,
        target_type: SuggestionTargetType,
        model_id: str,
        model_version: int,
    ) -> OptimizationModel:
        return cls(ModelId(model_id), tenant_id, target_type, model_version, ModelStatus.TRAINING)

    def mark_validating(self, metrics: dict[str, float]) -> None:
        if self.status != ModelStatus.TRAINING:
            raise InvalidModelTransition(self.status.value)
        self.status = ModelStatus.VALIDATING
        self.accuracy_metrics = dict(metrics)

    def fail(self) -> None:
        if self.status not in {ModelStatus.TRAINING, ModelStatus.VALIDATING}:
            raise InvalidModelTransition(self.status.value)
        self.status = ModelStatus.FAILED

    def deploy(self, tenant_id: TenantId, conformity_assessment_ref: str) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if self.status != ModelStatus.VALIDATING:
            raise InvalidModelTransition(self.status.value)
        if not conformity_assessment_ref:
            raise DomainInvariantViolation("conformity_assessment_ref required for deploy")
        thresholds = ACCURACY_THRESHOLDS[self.target_type]
        for key, minimum in thresholds.items():
            if self.accuracy_metrics.get(key, 0.0) < minimum:
                raise AccuracyThresholdNotMet(
                    f"{key}={self.accuracy_metrics.get(key)} < {minimum}"
                )
        now = datetime.now(UTC)
        self.status = ModelStatus.DEPLOYED
        self.conformity_assessment_ref = conformity_assessment_ref
        self.deployed_at = now
        self._pending_events.append(
            ModelDeployed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.model_id),
                model_id=str(self.model_id),
                target_type=self.target_type.value,
                model_version=self.model_version,
                accuracy_metrics=dict(self.accuracy_metrics),
            )
        )

    def deprecate(self, tenant_id: TenantId, superseded_by_version: int) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if self.status != ModelStatus.DEPLOYED:
            raise InvalidModelTransition(self.status.value)
        self.status = ModelStatus.DEPRECATED
        self._pending_events.append(
            ModelDeprecated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.model_id),
                model_id=str(self.model_id),
                superseded_by_version=superseded_by_version,
            )
        )

    def record_feedback(self) -> None:
        self.feedback_sample_count += 1

    def needs_retraining(self) -> bool:
        return self.feedback_sample_count >= self.retraining_threshold
''',
    )
    w(
        base / "domain" / "aggregates" / "autonomous_operations_policy.py",
        '''"""AutonomousOperationsPolicy — per-tenant autonomy / kill switch."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.evidence import (
    CONFIDENCE_FLOORS,
    DEFAULT_MIN_CONFIDENCE,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class AutonomousOperationsPolicy:
    __slots__ = (
        "_pending_events",
        "enabled_target_types",
        "kill_switch_active",
        "min_confidence_by_type",
        "review_required",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        tenant_id: TenantId,
        *,
        kill_switch_active: bool = False,
        min_confidence_by_type: dict[SuggestionTargetType, float] | None = None,
        enabled_target_types: list[SuggestionTargetType] | None = None,
        review_required: bool = True,
        updated_at: datetime | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.kill_switch_active = kill_switch_active
        self.min_confidence_by_type = dict(min_confidence_by_type or DEFAULT_MIN_CONFIDENCE)
        self.enabled_target_types = list(enabled_target_types or list(SuggestionTargetType))
        self.review_required = review_required
        self.updated_at = updated_at or datetime.now(UTC)
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def default(cls, tenant_id: TenantId) -> AutonomousOperationsPolicy:
        return cls(tenant_id)

    def min_confidence(self, target_type: SuggestionTargetType) -> float:
        return self.min_confidence_by_type.get(
            target_type, DEFAULT_MIN_CONFIDENCE[target_type]
        )

    def set_min_confidence(self, target_type: SuggestionTargetType, value: float) -> None:
        floor = CONFIDENCE_FLOORS[target_type]
        if value < floor:
            raise DomainInvariantViolation(f"min_confidence below floor {floor}")
        if value > 1.0:
            raise DomainInvariantViolation("min_confidence must be <= 1.0")
        self.min_confidence_by_type[target_type] = value
        self.updated_at = datetime.now(UTC)

    def activate_kill_switch(self) -> None:
        self.kill_switch_active = True
        self.updated_at = datetime.now(UTC)

    def reset_kill_switch(self) -> None:
        self.kill_switch_active = False
        self.updated_at = datetime.now(UTC)

    def allows(self, target_type: SuggestionTargetType) -> bool:
        return not self.kill_switch_active and target_type in self.enabled_target_types
''',
    )
    w(
        base / "domain" / "aggregates" / "suggestion_outcome.py",
        '''"""SuggestionOutcome — append-only feedback aggregate (C5)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from autonomous_intelligence.domain.value_objects.enums import OutcomeType, SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


@dataclass
class SuggestionOutcome:
    outcome_id: UUID
    suggestion_id: UUID
    tenant_id: TenantId
    target_type: SuggestionTargetType
    outcome_type: OutcomeType
    measurement_window_days: int
    baseline_metric: float
    observed_metric: float | None
    delta: float | None
    measured_at: datetime | None

    @classmethod
    def create_pending(
        cls,
        suggestion_id: UUID,
        tenant_id: TenantId,
        target_type: SuggestionTargetType,
        measurement_window_days: int,
        baseline_metric: float,
    ) -> SuggestionOutcome:
        return cls(
            uuid4(),
            suggestion_id,
            tenant_id,
            target_type,
            OutcomeType.PENDING,
            measurement_window_days,
            baseline_metric,
            None,
            None,
            None,
        )

    def record_measurement(self, observed_metric: float, measured_at: datetime) -> None:
        self.observed_metric = observed_metric
        self.delta = observed_metric - self.baseline_metric
        self.measured_at = measured_at
        self.outcome_type = OutcomeType.MEASURABLE
''',
    )

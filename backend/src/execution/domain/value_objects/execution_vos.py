"""Execution domain value objects."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from execution.domain.value_objects.enums import (
    AttackActionState,
    ChainIntegrityStatus,
    ImpactCeiling,
    KillSwitchArmedState,
    KillSwitchScope,
    RateLimitDecision,
    ScopeVerificationStatus,
    WorkerTrustLevel,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from execution.domain.value_objects.identifiers import (
        AttackActionId,
        EngagementId,
        ExecutionStepId,
        ExecutionWorkerId,
        OperationId,
        OperatorId,
        TargetId,
        TenantId,
    )


@dataclass(frozen=True, slots=True)
class TriggerAuthority:
    operator_id: OperatorId
    role: str

    def __post_init__(self) -> None:
        if not self.role.strip():
            raise ValueError("TriggerAuthority.role must not be empty")


@dataclass(frozen=True, slots=True)
class ReleaseAuthority:
    operator_id: OperatorId
    role: str

    def __post_init__(self) -> None:
        if not self.role.strip():
            raise ValueError("ReleaseAuthority.role must not be empty")


@dataclass(frozen=True, slots=True)
class TriggerReason:
    value: str

    def __post_init__(self) -> None:
        text = self.value.strip()
        if not text:
            raise ValueError("TriggerReason must not be empty")
        if len(text) > 2048:
            raise ValueError("TriggerReason must be at most 2048 characters")
        object.__setattr__(self, "value", text)


@dataclass(frozen=True, slots=True)
class TriggerHash:
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64:
            raise ValueError("TriggerHash must be a 64-char SHA-256 hex digest")

    @classmethod
    def compute(
        cls,
        scope: KillSwitchScope,
        state: KillSwitchArmedState,
        authority: TriggerAuthority,
        timestamp: datetime,
    ) -> TriggerHash:
        payload = (
            f"{scope.value}|{state.value}|{authority.operator_id}|"
            f"{timestamp.isoformat()}"
        )
        return cls(hashlib.sha256(payload.encode("utf-8")).hexdigest())


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    max_executions: int
    window_duration_seconds: int
    technique_category: str

    def __post_init__(self) -> None:
        if self.max_executions < 1:
            raise ValueError("max_executions must be >= 1")
        if self.window_duration_seconds < 1:
            raise ValueError("window_duration_seconds must be >= 1")
        if not self.technique_category.strip():
            raise ValueError("technique_category must not be empty")


@dataclass(frozen=True, slots=True)
class TechniqueRef:
    technique_id: str
    technique_category: str
    impact_ceiling: ImpactCeiling

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise ValueError("technique_id must not be empty")
        if not self.technique_category.strip():
            raise ValueError("technique_category must not be empty")


@dataclass(frozen=True, slots=True)
class TargetRef:
    target_id: TargetId

    def __str__(self) -> str:
        return str(self.target_id)


@dataclass(frozen=True, slots=True)
class ExecutionStepRef:
    step_id: ExecutionStepId
    operation_id: OperationId
    engagement_id: EngagementId

    def __str__(self) -> str:
        return str(self.step_id)


@dataclass(frozen=True, slots=True)
class WorkerRef:
    worker_id: ExecutionWorkerId

    def __str__(self) -> str:
        return str(self.worker_id)


@dataclass(frozen=True, slots=True)
class OperatorRef:
    operator_id: OperatorId

    def __str__(self) -> str:
        return str(self.operator_id)


@dataclass(frozen=True, slots=True)
class ActionInput:
    """Immutable parameters passed to the execution worker."""

    parameters: dict[str, object]

    def serialized(self) -> str:
        return json.dumps(self.parameters, sort_keys=True, separators=(",", ":"))

    def input_hash(self) -> str:
        return hashlib.sha256(self.serialized().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ActionOutputRef:
    output_hash: str
    storage_ref: str

    def __post_init__(self) -> None:
        if len(self.output_hash) != 64:
            raise ValueError("output_hash must be a 64-char SHA-256 hex digest")
        if not self.storage_ref.strip():
            raise ValueError("storage_ref must not be empty")


@dataclass(frozen=True, slots=True)
class ActionHash:
    value: str

    def __post_init__(self) -> None:
        if len(self.value) != 64:
            raise ValueError("ActionHash must be a 64-char SHA-256 hex digest")

    @classmethod
    def compute(
        cls,
        action_id: AttackActionId,
        target_ref: TargetRef,
        technique_ref: TechniqueRef,
        input_hash: str,
        execution_timestamp: datetime,
    ) -> ActionHash:
        payload = (
            f"{action_id}|{target_ref}|{technique_ref.technique_id}|"
            f"{input_hash}|{execution_timestamp.isoformat()}"
        )
        return cls(hashlib.sha256(payload.encode("utf-8")).hexdigest())


@dataclass(frozen=True, slots=True)
class SafetyCheckResult:
    kill_switch_state: KillSwitchArmedState
    scope_status: ScopeVerificationStatus
    rate_limit_decision: RateLimitDecision
    window_permitted: bool
    worker_capability_ok: bool


@dataclass(frozen=True, slots=True)
class AuthorizationToken:
    """Opaque proof that ExecutionAuthorizationService passed all checks (ADR-M29-001)."""

    token_id: str
    tenant_id: TenantId
    engagement_id: EngagementId
    operation_id: OperationId
    step_ref: ExecutionStepRef
    target_ref: TargetRef
    technique_ref: TechniqueRef
    operator_ref: OperatorRef
    worker_ref: WorkerRef | None
    safety: SafetyCheckResult
    issued_at: datetime
    scope_hash: str
    engagement_version: int


@dataclass(frozen=True, slots=True)
class ScopeSnapshot:
    """ACL snapshot from engagement context — local VOs only."""

    engagement_id: EngagementId
    tenant_id: TenantId
    authorized_target_ids: frozenset[UUID]
    scope_hash: str
    engagement_version: int
    state: str
    window_start: datetime | None
    window_end: datetime | None
    allowed_techniques: frozenset[str]
    kill_switch_field_hint: KillSwitchArmedState | None
    degraded: bool = False


@dataclass(frozen=True, slots=True)
class SignedCapabilityManifest:
    """Admin-signed worker capability declaration (Hardening §5)."""

    techniques: frozenset[str]
    trust_level: WorkerTrustLevel
    signer_operator_id: OperatorId
    signature: str
    signed_at: datetime

    def __post_init__(self) -> None:
        if not self.techniques:
            raise ValueError("SignedCapabilityManifest must declare at least one technique")
        if not self.signature.strip():
            raise ValueError("signature must not be empty")

    def manifest_hash(self) -> str:
        tech = ",".join(sorted(self.techniques))
        payload = (
            f"{tech}|{self.trust_level.value}|{self.signer_operator_id}|"
            f"{self.signature}|{self.signed_at.isoformat()}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ChainIntegrityReport:
    status: ChainIntegrityStatus
    journal_id: str
    entry_count: int
    broken_at_sequence: int | None = None
    detail: str = ""


_TERMINAL_ACTION_STATES: frozenset[AttackActionState] = frozenset(
    {
        AttackActionState.COMPLETED,
        AttackActionState.FAILED,
        AttackActionState.ABORTED,
        AttackActionState.TIMED_OUT,
    }
)


def is_terminal_action_state(state: AttackActionState) -> bool:
    return state in _TERMINAL_ACTION_STATES

"""ExecutionAuthorizationService — central 5-check safety gate (ADR-M29-001)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from execution.domain.exceptions.domain_exceptions import AuthorizationDenied
from execution.domain.services.execution_window_service import ExecutionWindowService
from execution.domain.value_objects.enums import (
    AuthorizationFailureReason,
    KillSwitchArmedState,
    RateLimitDecision,
    ScopeVerificationStatus,
)
from execution.domain.value_objects.execution_vos import (
    AuthorizationToken,
    SafetyCheckResult,
)

if TYPE_CHECKING:
    from datetime import datetime

    from execution.domain.aggregates.execution_worker import ExecutionWorker
    from execution.domain.services.kill_switch_evaluation_service import (
        KillSwitchEvaluationService,
    )
    from execution.domain.services.rate_limit_evaluation_service import (
        RateLimitEvaluationService,
    )
    from execution.domain.services.scope_verification_service import (
        ScopeVerificationService,
    )
    from execution.domain.services.worker_capability_verification_service import (
        WorkerCapabilityVerificationService,
    )
    from execution.domain.value_objects.execution_vos import (
        ExecutionStepRef,
        OperatorRef,
        RateLimitPolicy,
        TargetRef,
        TechniqueRef,
        WorkerRef,
    )
    from execution.domain.value_objects.identifiers import (
        EngagementId,
        OperationId,
        TenantId,
    )


class AuthorizationResult:
    __slots__ = ("failure_reason", "token")

    def __init__(
        self,
        token: AuthorizationToken | None,
        failure_reason: AuthorizationFailureReason | None = None,
    ) -> None:
        self.token = token
        self.failure_reason = failure_reason

    @property
    def permitted(self) -> bool:
        return self.token is not None


class ExecutionAuthorizationService:
    """
    Evaluates in fixed order (Hardening tech-debt rule 1):
    1. KillSwitch
    2. Scope
    3. RateLimit
    4. Window
    5. WorkerCapability

    Kill switch first; skip remaining checks if triggered.
    Phase 3: worker_ref=None skips check 5 (always passes).
    Phase 4: pass worker for full verification.
    """

    def __init__(
        self,
        kill_switch: KillSwitchEvaluationService,
        scope: ScopeVerificationService,
        rate_limit: RateLimitEvaluationService,
        window: ExecutionWindowService | None = None,
        worker_capability: WorkerCapabilityVerificationService | None = None,
    ) -> None:
        self._kill_switch = kill_switch
        self._scope = scope
        self._rate_limit = rate_limit
        self._window = window or ExecutionWindowService()
        self._worker_capability = worker_capability

    async def authorize(
        self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        operation_id: OperationId,
        step_ref: ExecutionStepRef,
        target_ref: TargetRef,
        technique_ref: TechniqueRef,
        operator_ref: OperatorRef,
        rate_limit_policy: RateLimitPolicy,
        now: datetime,
        *,
        worker: ExecutionWorker | None = None,
        worker_ref: WorkerRef | None = None,
        presented_scope_hash: str | None = None,
        presented_engagement_version: int | None = None,
        skip_remaining_on_kill_switch: bool = True,
    ) -> AuthorizationResult:
        # 1. Kill switch — ALWAYS first
        ks_state = await self._kill_switch.evaluate(
            tenant_id, engagement_id, operation_id
        )
        if ks_state != KillSwitchArmedState.ARMED:
            return AuthorizationResult(
                None, AuthorizationFailureReason.KILL_SWITCH_TRIGGERED
            )

        # 2. Scope
        scope_status, snapshot = await self._scope.verify(
            tenant_id,
            engagement_id,
            target_ref,
            technique_ref,
            presented_scope_hash=presented_scope_hash,
            presented_engagement_version=presented_engagement_version,
        )
        if scope_status != ScopeVerificationStatus.VERIFIED:
            return AuthorizationResult(
                None, AuthorizationFailureReason.SCOPE_VIOLATION
            )

        # 3. Rate limit
        rl_decision = await self._rate_limit.evaluate(
            tenant_id,
            target_ref.target_id,
            technique_ref,
            rate_limit_policy,
            engagement_id.value,
        )
        if rl_decision == RateLimitDecision.THROTTLED:
            return AuthorizationResult(
                None, AuthorizationFailureReason.RATE_LIMIT_THROTTLED
            )
        if rl_decision == RateLimitDecision.FORBIDDEN:
            return AuthorizationResult(
                None, AuthorizationFailureReason.RATE_LIMIT_FORBIDDEN
            )

        # 4. Execution window
        window_ok = self._window.is_within_window(
            now, snapshot.window_start, snapshot.window_end
        )
        if not window_ok:
            return AuthorizationResult(
                None, AuthorizationFailureReason.OUTSIDE_EXECUTION_WINDOW
            )

        # 5. Worker capability — Phase 3: skip when worker is None
        worker_ok = True
        effective_worker_ref = worker_ref
        if worker is not None:
            if self._worker_capability is None:
                from execution.domain.services.worker_capability_verification_service import (
                    WorkerCapabilityVerificationService,
                )

                capability = WorkerCapabilityVerificationService()
            else:
                capability = self._worker_capability
            worker_ok = capability.verify(worker, technique_ref)
            if not worker_ok:
                reason = AuthorizationFailureReason.WORKER_CAPABILITY_INSUFFICIENT
                if not worker.is_available():
                    reason = AuthorizationFailureReason.WORKER_UNAVAILABLE
                return AuthorizationResult(None, reason)
            from execution.domain.value_objects.execution_vos import WorkerRef

            effective_worker_ref = WorkerRef(worker_id=worker.worker_id)
        # else: Phase 3 stub — worker capability always passes when worker_ref is None

        _ = skip_remaining_on_kill_switch  # documented behavior above

        safety = SafetyCheckResult(
            kill_switch_state=KillSwitchArmedState.ARMED,
            scope_status=ScopeVerificationStatus.VERIFIED,
            rate_limit_decision=RateLimitDecision.PERMITTED,
            window_permitted=True,
            worker_capability_ok=worker_ok,
        )
        token = AuthorizationToken(
            token_id=str(uuid7()),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            operation_id=operation_id,
            step_ref=step_ref,
            target_ref=target_ref,
            technique_ref=technique_ref,
            operator_ref=operator_ref,
            worker_ref=effective_worker_ref,
            safety=safety,
            issued_at=now,
            scope_hash=snapshot.scope_hash,
            engagement_version=snapshot.engagement_version,
        )
        return AuthorizationResult(token)

    async def authorize_or_raise(self, **kwargs: object) -> AuthorizationToken:
        result = await self.authorize(**kwargs)  # type: ignore[arg-type]
        if result.token is None:
            raise AuthorizationDenied(
                result.failure_reason.value if result.failure_reason else "denied",
                result.failure_reason.value if result.failure_reason else "unknown",
            )
        return result.token

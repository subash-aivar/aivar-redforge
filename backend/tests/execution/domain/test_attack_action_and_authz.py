"""Domain tests: AttackAction, worker trust, authorization check order."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid7

import pytest
from tests.execution.fakes.repos import ConfigurableEngagementScope

from execution.domain.aggregates.attack_action import AttackAction
from execution.domain.aggregates.execution_worker import ExecutionWorker
from execution.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    WorkerTrustInsufficient,
)
from execution.domain.services.execution_authorization_service import (
    ExecutionAuthorizationService,
)
from execution.domain.services.execution_window_service import ExecutionWindowService
from execution.domain.services.kill_switch_evaluation_service import (
    KillSwitchEvaluationService,
)
from execution.domain.services.rate_limit_evaluation_service import (
    RateLimitEvaluationService,
)
from execution.domain.services.scope_verification_service import ScopeVerificationService
from execution.domain.services.worker_capability_verification_service import (
    WorkerCapabilityVerificationService,
)
from execution.domain.value_objects.enums import (
    AttackActionState,
    AuthorizationFailureReason,
    ImpactCeiling,
    KillSwitchArmedState,
    RateLimitDecision,
    ScopeVerificationStatus,
    WorkerTrustLevel,
    WorkerType,
)
from execution.domain.value_objects.execution_vos import (
    ActionInput,
    AuthorizationToken,
    ExecutionStepRef,
    OperatorRef,
    SafetyCheckResult,
    SignedCapabilityManifest,
    TargetRef,
    TechniqueRef,
)
from execution.domain.value_objects.identifiers import (
    EngagementId,
    ExecutionStepId,
    OperationId,
    OperatorId,
    TargetId,
    TenantId,
)
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore


def _token(
    tenant: TenantId,
    engagement: EngagementId,
    target: TargetId,
    technique: TechniqueRef,
    now: datetime,
) -> AuthorizationToken:
    op = OperationId(uuid7())
    step = ExecutionStepId(uuid7())
    return AuthorizationToken(
        token_id=str(uuid7()),
        tenant_id=tenant,
        engagement_id=engagement,
        operation_id=op,
        step_ref=ExecutionStepRef(step, op, engagement),
        target_ref=TargetRef(target),
        technique_ref=technique,
        operator_ref=OperatorRef(OperatorId(uuid7())),
        worker_ref=None,
        safety=SafetyCheckResult(
            kill_switch_state=KillSwitchArmedState.ARMED,
            scope_status=ScopeVerificationStatus.VERIFIED,
            rate_limit_decision=RateLimitDecision.PERMITTED,
            window_permitted=True,
            worker_capability_ok=True,
        ),
        issued_at=now,
        scope_hash="a" * 64,
        engagement_version=1,
    )


def test_attack_action_hash_and_seal() -> None:
    now = datetime.now(UTC)
    tenant = TenantId(uuid7())
    engagement = EngagementId(uuid7())
    target = TargetId(uuid7())
    technique = TechniqueRef("T1059", "execution", ImpactCeiling.PROBE)
    token = _token(tenant, engagement, target, technique, now)
    action = AttackAction.create_authorized(token, ActionInput({"cmd": "whoami"}), now)
    action.start(tenant, now)
    assert action.verify_integrity(now) is True
    action.complete(tenant, now)
    with pytest.raises(AggregateSealed):
        action.abort(tenant, "late", "op", now)
    assert action.state == AttackActionState.COMPLETED


def test_attack_action_tamper_detected() -> None:
    now = datetime.now(UTC)
    tenant = TenantId(uuid7())
    engagement = EngagementId(uuid7())
    target = TargetId(uuid7())
    technique = TechniqueRef("T1059", "execution", ImpactCeiling.PROBE)
    token = _token(tenant, engagement, target, technique, now)
    action = AttackAction.create_authorized(token, ActionInput({}), now)
    action.input_hash = "0" * 64
    assert action.verify_integrity(now) is False


def test_low_trust_cannot_exploit() -> None:
    now = datetime.now(UTC)
    tenant = TenantId(uuid7())
    manifest = SignedCapabilityManifest(
        techniques=frozenset({"T1003"}),
        trust_level=WorkerTrustLevel.LOW_TRUST,
        signer_operator_id=OperatorId(uuid7()),
        signature="sig",
        signed_at=now,
    )
    worker = ExecutionWorker.register(
        tenant, WorkerType.CLOUD_AGENT, "zone-a", manifest, now
    )
    with pytest.raises(WorkerTrustInsufficient):
        worker.assert_can_execute(
            TechniqueRef("T1003", "cred", ImpactCeiling.EXPLOIT)
        )


@pytest.mark.asyncio
async def test_authorization_kill_switch_first_skips_rest(
    scope_snapshot, rate_policy, technique, target_id, tenant_id, engagement_id, now
) -> None:
    store = InMemoryKillSwitchStore()
    # Mark engagement kill switch as triggered via direct state
    from execution.domain.aggregates.kill_switch_state import KillSwitchState
    from execution.domain.value_objects.enums import KillSwitchScope
    from execution.domain.value_objects.execution_vos import TriggerAuthority, TriggerReason

    ks = KillSwitchState.create_armed(
        tenant_id, KillSwitchScope.ENGAGEMENT, engagement_id.value, now
    )
    ks.trigger(
        tenant_id,
        TriggerAuthority(OperatorId(uuid7()), "redteam:admin"),
        TriggerReason("stop"),
        now,
    )
    await store.set_state(ks)

    scope_port = ConfigurableEngagementScope(scope_snapshot)
    scope_svc = ScopeVerificationService(scope_port)
    # Spy: if scope is called after kill switch, test fails intent
    scope_svc.verify = AsyncMock(side_effect=AssertionError("scope should be skipped"))  # type: ignore[method-assign]

    rate_svc = RateLimitEvaluationService(InMemoryRateLimitStore())
    auth = ExecutionAuthorizationService(
        KillSwitchEvaluationService(store),
        scope_svc,
        rate_svc,
        ExecutionWindowService(),
        WorkerCapabilityVerificationService(),
    )
    op = OperationId(uuid7())
    result = await auth.authorize(
        tenant_id,
        engagement_id,
        op,
        ExecutionStepRef(ExecutionStepId(uuid7()), op, engagement_id),
        TargetRef(target_id),
        technique,
        OperatorRef(OperatorId(uuid7())),
        rate_policy,
        now,
    )
    assert not result.permitted
    assert result.failure_reason == AuthorizationFailureReason.KILL_SWITCH_TRIGGERED
    scope_svc.verify.assert_not_called()

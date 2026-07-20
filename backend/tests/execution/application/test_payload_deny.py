"""Payload hash / approval denial at authorize_and_start."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid7

import pytest
from tests.execution.fakes.repos import (
    ConfigurableEngagementScope,
    FakeEventPublisher,
    FakeUnitOfWork,
)

from execution.application.commands.execution_commands import AuthorizeAndStartAttackAction
from execution.application.exceptions import ApplicationAuthorizationError
from execution.application.services.execution_application_service import (
    ExecutionApplicationService,
)
from execution.domain.ports.i_payload_query_port import (
    IPayloadQueryPort,
    PayloadDispatchCheck,
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
from execution.domain.services.worker_assignment_service import WorkerAssignmentService
from execution.domain.services.worker_capability_verification_service import (
    WorkerCapabilityVerificationService,
)
from execution.domain.value_objects.enums import (
    AuthorizationFailureReason,
    JournalEntryType,
)
from execution.domain.value_objects.execution_vos import ScopeSnapshot
from execution.domain.value_objects.identifiers import EngagementId, TargetId, TenantId
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore
from execution.infrastructure.technique.in_memory_dispatcher import InMemoryTechniqueDispatcher


class HashMismatchPayloadPort(IPayloadQueryPort):
    async def verify_for_dispatch(
        self,
        tenant_id: UUID,
        payload_id: UUID,
        expected_hash: str | None = None,
    ) -> PayloadDispatchCheck:
        return PayloadDispatchCheck(
            approved=True,
            hash_ok=False,
            failure_reason=AuthorizationFailureReason.PAYLOAD_HASH_MISMATCH.value,
        )


def _build(
    payload_port: IPayloadQueryPort,
    scope_snapshot: ScopeSnapshot,
) -> tuple[ExecutionApplicationService, FakeUnitOfWork]:
    kill_store = InMemoryKillSwitchStore()
    rate_store = InMemoryRateLimitStore()
    uow = FakeUnitOfWork()
    events = FakeEventPublisher()
    auth = ExecutionAuthorizationService(
        KillSwitchEvaluationService(kill_store),
        ScopeVerificationService(ConfigurableEngagementScope(scope_snapshot)),
        RateLimitEvaluationService(rate_store),
        ExecutionWindowService(),
        WorkerCapabilityVerificationService(),
    )

    def uow_factory() -> FakeUnitOfWork:
        return FakeUnitOfWork(
            kill_switches=uow.kill_switches,  # type: ignore[arg-type]
            journals=uow.journals,  # type: ignore[arg-type]
            attack_actions=uow.attack_actions,  # type: ignore[arg-type]
            workers=uow.workers,  # type: ignore[arg-type]
        )

    svc = ExecutionApplicationService(
        uow_factory,
        events,
        auth,
        WorkerAssignmentService(uow.workers, WorkerCapabilityVerificationService()),  # type: ignore[arg-type]
        InMemoryTechniqueDispatcher(),
        kill_switch_store_sync=kill_store.set_state,
        payload_query=payload_port,
    )
    return svc, uow


@pytest.mark.asyncio
async def test_payload_hash_mismatch_denies_authorize() -> None:
    tenant = TenantId(uuid7())
    engagement = EngagementId(uuid7())
    target = TargetId(uuid7())
    now = datetime.now(UTC)
    scope = ScopeSnapshot(
        engagement_id=engagement,
        tenant_id=tenant,
        authorized_target_ids=frozenset({target}),
        scope_hash="abc",
        engagement_version=1,
        state="Active",
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=1),
        allowed_techniques=frozenset({"T1059"}),
        kill_switch_field_hint=None,
        degraded=False,
    )
    svc, uow = _build(HashMismatchPayloadPort(), scope)
    with pytest.raises(ApplicationAuthorizationError) as exc:
        await svc.authorize_and_start_attack_action(
            AuthorizeAndStartAttackAction(
                tenant_id=tenant.value,
                engagement_id=engagement.value,
                operation_id=uuid7(),
                step_id=uuid7(),
                target_id=target.value,
                technique_id="T1059",
                technique_category="execution",
                impact_ceiling="Probe",
                operator_id=uuid7(),
                worker_id=None,
                action_parameters={},
                rate_limit_max=10,
                rate_limit_window_seconds=60,
                presented_scope_hash="abc",
                presented_engagement_version=1,
                payload_id=uuid7(),
                expected_payload_hash="0" * 64,
            )
        )
    assert AuthorizationFailureReason.PAYLOAD_HASH_MISMATCH.value in str(exc.value)
    journal = await uow.journals.find_by_engagement(engagement, tenant)
    assert journal is not None
    assert any(
        e.entry_type == JournalEntryType.SAFETY_CHECK_FAILED for e in journal.entries
    )

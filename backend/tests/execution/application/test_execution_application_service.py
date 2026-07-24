"""Application service tests for execution Phase 3/4."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from tests.execution.fakes.repos import (
    ConfigurableEngagementScope,
    FakeEventPublisher,
    FakeUnitOfWork,
)

from execution.application.commands.execution_commands import (
    AuthorizeAndStartAttackAction,
    ReleaseKillSwitch,
    TriggerKillSwitch,
)
from execution.application.exceptions import ApplicationAuthorizationError
from execution.application.queries.execution_queries import QueryJournalIntegrity
from execution.application.services.execution_application_service import (
    ExecutionApplicationService,
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
    CISO_ROLE,
    ChainIntegrityStatus,
    JournalEntryType,
    KillSwitchArmedState,
    KillSwitchScope,
)
from execution.domain.value_objects.execution_vos import ScopeSnapshot
from execution.domain.value_objects.identifiers import (
    TargetId,
)
from execution.infrastructure.redis.in_memory_kill_switch_store import InMemoryKillSwitchStore
from execution.infrastructure.redis.in_memory_rate_limit_store import InMemoryRateLimitStore
from execution.infrastructure.technique.in_memory_dispatcher import InMemoryTechniqueDispatcher


def _build_service(
    *,
    scope_snapshot: ScopeSnapshot,
    kill_store: InMemoryKillSwitchStore | None = None,
    rate_store: InMemoryRateLimitStore | None = None,
    uow: FakeUnitOfWork | None = None,
) -> tuple[ExecutionApplicationService, FakeUnitOfWork, FakeEventPublisher, InMemoryKillSwitchStore]:
    kill_store = kill_store or InMemoryKillSwitchStore()
    rate_store = rate_store or InMemoryRateLimitStore()
    uow = uow or FakeUnitOfWork()
    events = FakeEventPublisher()
    scope_port = ConfigurableEngagementScope(scope_snapshot)
    auth = ExecutionAuthorizationService(
        KillSwitchEvaluationService(kill_store),
        ScopeVerificationService(scope_port),
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
    )
    return svc, uow, events, kill_store


@pytest.mark.asyncio
async def test_trigger_release_same_operator_rejected(
    scope_snapshot, tenant_id, engagement_id
) -> None:
    svc, _uow, _, _ = _build_service(scope_snapshot=scope_snapshot)
    op = uuid7()
    await svc.trigger_kill_switch(
        TriggerKillSwitch(
            tenant_id=tenant_id,
            scope=KillSwitchScope.ENGAGEMENT.value,
            scope_ref=engagement_id.value,
            authority_operator_id=op,
            authority_role="redteam:admin",
            reason="emergency",
        )
    )
    with pytest.raises(ApplicationAuthorizationError):
        await svc.release_kill_switch(
            ReleaseKillSwitch(
                tenant_id=tenant_id,
                scope=KillSwitchScope.ENGAGEMENT.value,
                scope_ref=engagement_id.value,
                releasing_operator_id=op,
                releasing_role="redteam:admin",
            )
        )


@pytest.mark.asyncio
async def test_platform_two_party_release(scope_snapshot, tenant_id) -> None:
    svc, _, _, _ = _build_service(scope_snapshot=scope_snapshot)
    trigger_op = uuid7()
    ciso = uuid7()
    legal = uuid7()
    await svc.trigger_kill_switch(
        TriggerKillSwitch(
            tenant_id=tenant_id,
            scope=KillSwitchScope.PLATFORM_WIDE.value,
            scope_ref=tenant_id.value,
            authority_operator_id=trigger_op,
            authority_role="redteam:admin",
            reason="global halt",
        )
    )
    with pytest.raises(ApplicationAuthorizationError):
        await svc.release_kill_switch(
            ReleaseKillSwitch(
                tenant_id=tenant_id,
                scope=KillSwitchScope.PLATFORM_WIDE.value,
                scope_ref=tenant_id.value,
                releasing_operator_id=ciso,
                releasing_role=CISO_ROLE,
            )
        )
    dto = await svc.release_kill_switch(
        ReleaseKillSwitch(
            tenant_id=tenant_id,
            scope=KillSwitchScope.PLATFORM_WIDE.value,
            scope_ref=tenant_id.value,
            releasing_operator_id=ciso,
            releasing_role=CISO_ROLE,
            countersigning_operator_id=legal,
            countersigning_role="legal:oversight",
        )
    )
    assert dto.armed_state == KillSwitchArmedState.RELEASED.value


@pytest.mark.asyncio
async def test_authorize_blocked_when_kill_switched(
    scope_snapshot, tenant_id, engagement_id, target_id
) -> None:
    svc, _, _, _ = _build_service(scope_snapshot=scope_snapshot)
    await svc.trigger_kill_switch(
        TriggerKillSwitch(
            tenant_id=tenant_id,
            scope=KillSwitchScope.ENGAGEMENT.value,
            scope_ref=engagement_id.value,
            authority_operator_id=uuid7(),
            authority_role="redteam:admin",
            reason="halt",
        )
    )
    with pytest.raises(ApplicationAuthorizationError) as exc:
        await svc.authorize_and_start_attack_action(
            AuthorizeAndStartAttackAction(
                tenant_id=tenant_id,
                engagement_id=engagement_id.value,
                operation_id=uuid7(),
                step_id=uuid7(),
                target_id=target_id.value,
                technique_id="T1059",
                technique_category="execution",
                impact_ceiling="Probe",
                operator_id=uuid7(),
                worker_id=None,
                action_parameters={},
                rate_limit_max=10,
                rate_limit_window_seconds=60,
            )
        )
    assert "KillSwitchTriggered" in str(exc.value)


@pytest.mark.asyncio
async def test_scope_violation_journals_entry(
    scope_snapshot, tenant_id, engagement_id
) -> None:
    # Target not in authorized set
    bad_target = TargetId(uuid7())
    snap = ScopeSnapshot(
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        authorized_target_ids=frozenset({uuid7()}),
        scope_hash="b" * 64,
        engagement_version=1,
        state="Active",
        window_start=datetime.now(UTC) - timedelta(hours=1),
        window_end=datetime.now(UTC) + timedelta(hours=1),
        allowed_techniques=frozenset({"T1059"}),
        kill_switch_field_hint=None,
    )
    svc, uow, _, _ = _build_service(scope_snapshot=snap)
    with pytest.raises(ApplicationAuthorizationError):
        await svc.authorize_and_start_attack_action(
            AuthorizeAndStartAttackAction(
                tenant_id=tenant_id,
                engagement_id=engagement_id.value,
                operation_id=uuid7(),
                step_id=uuid7(),
                target_id=bad_target.value,
                technique_id="T1059",
                technique_category="execution",
                impact_ceiling="Probe",
                operator_id=uuid7(),
                worker_id=None,
                action_parameters={},
                rate_limit_max=10,
                rate_limit_window_seconds=60,
            )
        )
    journal = await uow.journals.find_by_engagement(engagement_id, tenant_id)
    assert journal is not None
    assert any(
        e.entry_type == JournalEntryType.SCOPE_VIOLATION_ATTEMPTED for e in journal.entries
    )


@pytest.mark.asyncio
async def test_rate_limit_throttle_journals(
    scope_snapshot, tenant_id, engagement_id, target_id
) -> None:
    rate_store = InMemoryRateLimitStore()
    # Pre-consume all permits
    from execution.domain.services.rate_limit_evaluation_service import (
        RateLimitEvaluationService,
    )
    from execution.domain.value_objects.enums import ImpactCeiling
    from execution.domain.value_objects.execution_vos import RateLimitPolicy, TechniqueRef

    rl = RateLimitEvaluationService(rate_store)
    tech = TechniqueRef("T1059", "execution", ImpactCeiling.PROBE)
    policy = RateLimitPolicy(1, 60, "execution")
    await rl.evaluate(tenant_id, target_id, tech, policy, engagement_id.value)

    svc, uow, _, _ = _build_service(scope_snapshot=scope_snapshot, rate_store=rate_store)
    with pytest.raises(ApplicationAuthorizationError):
        await svc.authorize_and_start_attack_action(
            AuthorizeAndStartAttackAction(
                tenant_id=tenant_id,
                engagement_id=engagement_id.value,
                operation_id=uuid7(),
                step_id=uuid7(),
                target_id=target_id.value,
                technique_id="T1059",
                technique_category="execution",
                impact_ceiling="Probe",
                operator_id=uuid7(),
                worker_id=None,
                action_parameters={},
                rate_limit_max=1,
                rate_limit_window_seconds=60,
            )
        )
    journal = await uow.journals.find_by_engagement(engagement_id, tenant_id)
    assert journal is not None
    assert any(e.entry_type == JournalEntryType.SAFETY_CHECK_FAILED for e in journal.entries)


@pytest.mark.asyncio
async def test_idempotent_authorize(
    scope_snapshot, tenant_id, engagement_id, target_id
) -> None:
    svc, _, _, _ = _build_service(scope_snapshot=scope_snapshot)
    step_id = uuid7()
    cmd = AuthorizeAndStartAttackAction(
        tenant_id=tenant_id,
        engagement_id=engagement_id.value,
        operation_id=uuid7(),
        step_id=step_id,
        target_id=target_id.value,
        technique_id="T1059",
        technique_category="execution",
        impact_ceiling="Probe",
        operator_id=uuid7(),
        worker_id=None,
        action_parameters={"x": 1},
        rate_limit_max=10,
        rate_limit_window_seconds=60,
    )
    first = await svc.authorize_and_start_attack_action(cmd)
    second = await svc.authorize_and_start_attack_action(cmd)
    assert first.action_id == second.action_id


@pytest.mark.asyncio
async def test_query_journal_integrity_detects_break(
    scope_snapshot, tenant_id, engagement_id
) -> None:
    svc, uow, _, _ = _build_service(scope_snapshot=scope_snapshot)
    from execution.application.commands.execution_commands import (
        AppendJournalEntry,
        CreateJournal,
    )

    await svc.create_journal(
        CreateJournal(tenant_id=tenant_id, engagement_id=engagement_id.value)
    )
    await svc.append_journal_entry(
        AppendJournalEntry(
            tenant_id=tenant_id,
            engagement_id=engagement_id.value,
            entry_type=JournalEntryType.ACTION_STARTED.value,
            content="a",
            system_attribution="sys",
        )
    )
    journal = await uow.journals.find_by_engagement(engagement_id, tenant_id)
    assert journal is not None
    journal.entries[0].content = "BROKEN"
    report = await svc.query_journal_integrity(
        QueryJournalIntegrity(tenant_id=tenant_id, engagement_id=engagement_id.value)
    )
    assert report.status == ChainIntegrityStatus.BROKEN.value

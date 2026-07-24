"""ExecutionApplicationService — Phase 3 safety + Phase 4 pipeline use cases."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from execution.application._validation import (
    validate_limit,
    validate_offset,
    validate_str,
    validate_uuid,
)
from execution.application.dtos.execution_dtos import (
    AttackActionDTO,
    ChainIntegrityReportDTO,
    ExecutionWorkerDTO,
    JournalDTO,
    JournalEntryDTO,
    KillSwitchDTO,
)
from execution.application.exceptions import (
    ApplicationAuthorizationError,
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from execution.domain.aggregates.attack_action import AttackAction
from execution.domain.aggregates.execution_journal import ExecutionJournal
from execution.domain.aggregates.execution_worker import ExecutionWorker
from execution.domain.aggregates.kill_switch_state import KillSwitchState
from execution.domain.exceptions.domain_exceptions import (
    PlatformWideReleaseAuthorizationInsufficient,
    SameOperatorReleaseForbidden,
)
from execution.domain.ports.i_payload_query_port import PayloadDispatchCheck
from execution.domain.value_objects.enums import (
    AuthorizationFailureReason,
    ImpactCeiling,
    JournalEntryType,
    KillSwitchScope,
    WorkerHealthStatus,
    WorkerTrustLevel,
    WorkerType,
)
from execution.domain.value_objects.execution_vos import (
    ActionInput,
    ActionOutputRef,
    ExecutionStepRef,
    OperatorRef,
    RateLimitPolicy,
    ReleaseAuthority,
    SignedCapabilityManifest,
    TargetRef,
    TechniqueRef,
    TriggerAuthority,
    TriggerReason,
    WorkerRef,
)
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

if TYPE_CHECKING:
    from collections.abc import Callable

    from execution.application.commands.execution_commands import (
        AbortAttackAction,
        AppendJournalEntry,
        AuthorizeAndStartAttackAction,
        CompleteAttackAction,
        CreateJournal,
        DecommissionExecutionWorker,
        FailAttackAction,
        ReArmKillSwitch,
        RecordActionOutput,
        RecordWorkerHeartbeat,
        RegisterExecutionWorker,
        ReleaseKillSwitch,
        TriggerKillSwitch,
    )
    from execution.application.ports.i_unit_of_work import IEventPublisher, IUnitOfWork
    from execution.application.queries.execution_queries import (
        GetAttackAction,
        GetExecutionWorker,
        GetJournal,
        GetKillSwitch,
        ListAttackActionsByOperation,
        ListAvailableWorkers,
        QueryJournalIntegrity,
    )
    from execution.domain.ports.i_payload_query_port import IPayloadQueryPort
    from execution.domain.ports.i_technique_execution_port import ITechniqueExecutionPort
    from execution.domain.services.execution_authorization_service import (
        ExecutionAuthorizationService,
    )
    from execution.domain.services.worker_assignment_service import WorkerAssignmentService

logger = logging.getLogger(__name__)


class ExecutionApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        authorization_service: ExecutionAuthorizationService,
        worker_assignment: WorkerAssignmentService,
        technique_port: ITechniqueExecutionPort,
        kill_switch_store_sync: Callable[[KillSwitchState], Any] | None = None,
        payload_query: IPayloadQueryPort | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._authorization = authorization_service
        self._worker_assignment = worker_assignment
        self._technique_port = technique_port
        self._kill_switch_store_sync = kill_switch_store_sync
        self._payload_query = payload_query

    # ── Phase 3: Kill switch ──────────────────────────────────────────

    async def trigger_kill_switch(self, cmd: TriggerKillSwitch) -> KillSwitchDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.scope_ref, "scope_ref")
        validate_uuid(cmd.authority_operator_id, "authority_operator_id")
        validate_str(cmd.reason, "reason", 2048)
        scope = self._parse_scope(cmd.scope)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            ks = await uow.kill_switches.find_by_scope(tenant, scope, cmd.scope_ref)
            if ks is None:
                ks = KillSwitchState.create_armed(tenant, scope, cmd.scope_ref, now)
            ks.trigger(
                tenant,
                TriggerAuthority(
                    OperatorId(cmd.authority_operator_id), cmd.authority_role
                ),
                TriggerReason(cmd.reason),
                now,
            )
            await uow.kill_switches.save(ks)
            await self._sync_kill_switch_store(ks)
            await self._journal_kill_switch(
                uow, tenant, scope, cmd.scope_ref, cmd.reason, now,
                OperatorId(cmd.authority_operator_id),
            )
            await uow.commit()
            await self._publish([ks])
            return self._kill_switch_dto(ks)

    async def release_kill_switch(self, cmd: ReleaseKillSwitch) -> KillSwitchDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.scope_ref, "scope_ref")
        validate_uuid(cmd.releasing_operator_id, "releasing_operator_id")
        scope = self._parse_scope(cmd.scope)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        countersign = None
        if cmd.countersigning_operator_id is not None:
            if not cmd.countersigning_role:
                raise ApplicationValidationError(
                    "countersigning_role", "required when countersigning_operator_id set"
                )
            countersign = ReleaseAuthority(
                OperatorId(cmd.countersigning_operator_id),
                cmd.countersigning_role,
            )

        async with self._uow_factory() as uow:
            ks = await uow.kill_switches.find_by_scope(tenant, scope, cmd.scope_ref)
            if ks is None:
                raise ApplicationNotFoundError("KillSwitch", f"{scope.value}:{cmd.scope_ref}")
            try:
                ks.release(
                    tenant,
                    ReleaseAuthority(
                        OperatorId(cmd.releasing_operator_id), cmd.releasing_role
                    ),
                    now,
                    countersigning=countersign,
                )
            except SameOperatorReleaseForbidden as exc:
                raise ApplicationAuthorizationError(str(exc)) from exc
            except PlatformWideReleaseAuthorizationInsufficient as exc:
                raise ApplicationAuthorizationError(str(exc)) from exc
            await uow.kill_switches.save(ks)
            await self._sync_kill_switch_store(ks)
            await uow.commit()
            await self._publish([ks])
            return self._kill_switch_dto(ks)

    async def re_arm_kill_switch(self, cmd: ReArmKillSwitch) -> KillSwitchDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.scope_ref, "scope_ref")
        scope = self._parse_scope(cmd.scope)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            ks = await uow.kill_switches.find_by_scope(tenant, scope, cmd.scope_ref)
            if ks is None:
                raise ApplicationNotFoundError("KillSwitch", f"{scope.value}:{cmd.scope_ref}")
            ks.re_arm(
                tenant,
                TriggerAuthority(
                    OperatorId(cmd.authority_operator_id), cmd.authority_role
                ),
                now,
            )
            await uow.kill_switches.save(ks)
            await self._sync_kill_switch_store(ks)
            await uow.commit()
            await self._publish([ks])
            return self._kill_switch_dto(ks)

    async def get_kill_switch(self, query: GetKillSwitch) -> KillSwitchDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        scope = self._parse_scope(query.scope)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            ks = await uow.kill_switches.find_by_scope(tenant, scope, query.scope_ref)
            if ks is None:
                raise ApplicationNotFoundError(
                    "KillSwitch", f"{scope.value}:{query.scope_ref}"
                )
            return self._kill_switch_dto(ks)

    # ── Phase 3: Journal ──────────────────────────────────────────────

    async def create_journal(self, cmd: CreateJournal) -> JournalDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        tenant = cmd.tenant_id
        engagement = EngagementId(cmd.engagement_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            existing = await uow.journals.find_by_engagement(engagement, tenant)
            if existing is not None:
                raise ApplicationConflictError(
                    f"Journal already exists for engagement {cmd.engagement_id}"
                )
            journal = ExecutionJournal.create(tenant, engagement, now)
            await uow.journals.save(journal)
            await uow.commit()
            await self._publish([journal])
            return self._journal_dto(journal)

    async def ensure_journal_for_engagement(
        self, tenant_id: TenantId, engagement_id: EngagementId, now: datetime
    ) -> ExecutionJournal:
        async with self._uow_factory() as uow:
            existing = await uow.journals.find_by_engagement(engagement_id, tenant_id)
            if existing is not None:
                return existing
            journal = ExecutionJournal.create(tenant_id, engagement_id, now)
            await uow.journals.save(journal)
            await uow.commit()
            await self._publish([journal])
            return journal

    async def append_journal_entry(self, cmd: AppendJournalEntry) -> JournalEntryDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        validate_str(cmd.content, "content", 8192)
        tenant = cmd.tenant_id
        engagement = EngagementId(cmd.engagement_id)
        entry_type = JournalEntryType(cmd.entry_type)
        now = datetime.now(UTC)
        attribution = (
            OperatorId(cmd.attribution_operator_id)
            if cmd.attribution_operator_id
            else None
        )

        async with self._uow_factory() as uow:
            journal = await uow.journals.find_by_engagement(engagement, tenant)
            if journal is None:
                journal = ExecutionJournal.create(tenant, engagement, now)
            entry = journal.append_entry(
                tenant,
                entry_type,
                cmd.content,
                now,
                attribution=attribution,
                system_attribution=cmd.system_attribution,
            )
            await uow.journals.save(journal)
            await uow.commit()
            await self._publish([journal])
            return JournalEntryDTO(
                entry_id=str(entry.entry_id),
                entry_type=entry.entry_type.value,
                sequence_number=entry.sequence_number,
                entry_hash=entry.entry_hash,
                previous_entry_hash=entry.previous_entry_hash,
                content=entry.content,
                occurred_at=entry.occurred_at.isoformat(),
            )

    async def get_journal(self, query: GetJournal) -> JournalDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        tenant = query.tenant_id
        engagement = EngagementId(query.engagement_id)
        async with self._uow_factory() as uow:
            journal = await uow.journals.find_by_engagement(engagement, tenant)
            if journal is None:
                raise ApplicationNotFoundError("ExecutionJournal", str(query.engagement_id))
            return self._journal_dto(journal)

    async def query_journal_integrity(
        self, query: QueryJournalIntegrity
    ) -> ChainIntegrityReportDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        tenant = query.tenant_id
        engagement = EngagementId(query.engagement_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            journal = await uow.journals.find_by_engagement(engagement, tenant)
            if journal is None:
                raise ApplicationNotFoundError("ExecutionJournal", str(query.engagement_id))
            report = journal.verify_chain_integrity(now)
            # Persist any integrity-failed security events
            await uow.journals.save(journal)
            await uow.commit()
            await self._publish([journal])
            return ChainIntegrityReportDTO(
                status=report.status.value,
                journal_id=report.journal_id,
                entry_count=report.entry_count,
                broken_at_sequence=report.broken_at_sequence,
                detail=report.detail,
            )

    # ── Phase 4: Attack actions ───────────────────────────────────────

    async def authorize_and_start_attack_action(
        self, cmd: AuthorizeAndStartAttackAction
    ) -> AttackActionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.engagement_id, "engagement_id")
        validate_uuid(cmd.operation_id, "operation_id")
        validate_uuid(cmd.step_id, "step_id")
        validate_uuid(cmd.target_id, "target_id")
        validate_str(cmd.technique_id, "technique_id", 256)
        tenant = cmd.tenant_id
        engagement = EngagementId(cmd.engagement_id)
        operation = OperationId(cmd.operation_id)
        step = ExecutionStepId(cmd.step_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            # Idempotency: same ExecutionStepRef non-terminal → return existing
            existing = await uow.attack_actions.find_non_terminal_by_step(step, tenant)
            if existing is not None:
                return self._attack_action_dto(existing)

            technique = TechniqueRef(
                cmd.technique_id,
                cmd.technique_category,
                ImpactCeiling(cmd.impact_ceiling),
            )
            target = TargetRef(TargetId(cmd.target_id))
            step_ref = ExecutionStepRef(step, operation, engagement)
            operator_ref = OperatorRef(OperatorId(cmd.operator_id))
            policy = RateLimitPolicy(
                cmd.rate_limit_max,
                cmd.rate_limit_window_seconds,
                cmd.technique_category,
            )

            worker = None
            if cmd.worker_id is not None:
                worker = await uow.workers.find_by_id(
                    ExecutionWorkerId(cmd.worker_id), tenant
                )
                if worker is None:
                    raise ApplicationNotFoundError("ExecutionWorker", str(cmd.worker_id))

            if cmd.payload_id is not None and self._payload_query is not None:
                check = await self._payload_query.verify_for_dispatch(
                    cmd.tenant_id,
                    cmd.payload_id,
                    cmd.expected_payload_hash,
                )
                payload_failure = self._payload_failure_reason(check)
                if payload_failure is not None:
                    await self._journal_authorization_failure(
                        uow,
                        tenant,
                        engagement,
                        payload_failure,
                        cmd,
                        now,
                    )
                    journal = await uow.journals.find_by_engagement(engagement, tenant)
                    await uow.commit()
                    if journal is not None:
                        await self._publish([journal])
                    raise ApplicationAuthorizationError(
                        f"Authorization denied: {payload_failure.value}",
                        payload_failure.value,
                    )

            result = await self._authorization.authorize(
                tenant,
                engagement,
                operation,
                step_ref,
                target,
                technique,
                operator_ref,
                policy,
                now,
                worker=worker,
                presented_scope_hash=cmd.presented_scope_hash,
                presented_engagement_version=cmd.presented_engagement_version,
            )

            if not result.permitted:
                await self._journal_authorization_failure(
                    uow,
                    tenant,
                    engagement,
                    result.failure_reason,
                    cmd,
                    now,
                )
                journal = await uow.journals.find_by_engagement(engagement, tenant)
                await uow.commit()
                if journal is not None:
                    await self._publish([journal])
                raise ApplicationAuthorizationError(
                    f"Authorization denied: {result.failure_reason}",
                    result.failure_reason.value if result.failure_reason else None,
                )

            assert result.token is not None
            action_input = ActionInput(dict(cmd.action_parameters))
            action = AttackAction.create_authorized(result.token, action_input, now)
            action.start(tenant, now)

            if worker is not None:
                worker.assign_action(tenant, str(action.action_id), technique, now)
                await uow.workers.save(worker)
                if cmd.payload_id is not None and self._payload_query is not None:
                    recheck = await self._payload_query.verify_for_dispatch(
                        cmd.tenant_id,
                        cmd.payload_id,
                        cmd.expected_payload_hash,
                    )
                    recheck_failure = self._payload_failure_reason(recheck)
                    if recheck_failure is not None:
                        await self._journal_authorization_failure(
                            uow,
                            tenant,
                            engagement,
                            recheck_failure,
                            cmd,
                            now,
                        )
                        journal = await uow.journals.find_by_engagement(
                            engagement, tenant
                        )
                        await uow.commit()
                        if journal is not None:
                            await self._publish([journal])
                        raise ApplicationAuthorizationError(
                            f"Dispatch denied: {recheck_failure.value}",
                            recheck_failure.value,
                        )
                await self._technique_port.dispatch(
                    action.action_id,
                    WorkerRef(worker.worker_id),
                    action_input,
                    payload_id=cmd.payload_id,
                    expected_payload_hash=cmd.expected_payload_hash,
                )

            journal = await uow.journals.find_by_engagement(engagement, tenant)
            if journal is None:
                journal = ExecutionJournal.create(tenant, engagement, now)
            journal.append_entry(
                tenant,
                JournalEntryType.ACTION_STARTED,
                f"action={action.action_id} step={step} technique={cmd.technique_id}",
                now,
                attribution=OperatorId(cmd.operator_id),
            )
            await uow.journals.save(journal)
            await uow.attack_actions.save(action)
            await uow.commit()
            aggregates: list[Any] = [action, journal]
            if worker is not None:
                aggregates.append(worker)
            await self._publish(aggregates)
            return self._attack_action_dto(action)

    async def abort_attack_action(self, cmd: AbortAttackAction) -> AttackActionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.action_id, "action_id")
        validate_str(cmd.abort_reason, "abort_reason", 2048)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            action = await uow.attack_actions.find_by_id(
                AttackActionId(cmd.action_id), tenant
            )
            if action is None:
                raise ApplicationNotFoundError("AttackAction", str(cmd.action_id))
            action.abort(
                tenant, cmd.abort_reason, str(cmd.authority_operator_id), now
            )
            await self._technique_port.signal_abort(action.action_id, cmd.abort_reason)
            journal = await uow.journals.find_by_engagement(action.engagement_id, tenant)
            if journal is not None:
                journal.append_entry(
                    tenant,
                    JournalEntryType.ACTION_ABORTED,
                    f"action={action.action_id} reason={cmd.abort_reason}",
                    now,
                    attribution=OperatorId(cmd.authority_operator_id),
                )
                await uow.journals.save(journal)
            await uow.attack_actions.save(action)
            await uow.commit()
            to_publish: list[Any] = [action]
            if journal is not None:
                to_publish.append(journal)
            await self._publish(to_publish)
            return self._attack_action_dto(action)

    async def complete_attack_action(self, cmd: CompleteAttackAction) -> AttackActionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        output_ref = None
        if cmd.output_hash and cmd.output_storage_ref:
            output_ref = ActionOutputRef(cmd.output_hash, cmd.output_storage_ref)

        async with self._uow_factory() as uow:
            action = await uow.attack_actions.find_by_id(
                AttackActionId(cmd.action_id), tenant
            )
            if action is None:
                raise ApplicationNotFoundError("AttackAction", str(cmd.action_id))
            action.complete(tenant, now, output_ref)
            journal = await uow.journals.find_by_engagement(action.engagement_id, tenant)
            if journal is not None:
                journal.append_entry(
                    tenant,
                    JournalEntryType.ACTION_COMPLETED,
                    f"action={action.action_id}",
                    now,
                    system_attribution="worker",
                )
                await uow.journals.save(journal)
            await uow.attack_actions.save(action)
            await uow.commit()
            to_publish: list[Any] = [action]
            if journal is not None:
                to_publish.append(journal)
            await self._publish(to_publish)
            return self._attack_action_dto(action)

    async def fail_attack_action(self, cmd: FailAttackAction) -> AttackActionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.failure_reason, "failure_reason", 2048)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            action = await uow.attack_actions.find_by_id(
                AttackActionId(cmd.action_id), tenant
            )
            if action is None:
                raise ApplicationNotFoundError("AttackAction", str(cmd.action_id))
            action.fail(tenant, cmd.failure_reason, now)
            journal = await uow.journals.find_by_engagement(action.engagement_id, tenant)
            if journal is not None:
                journal.append_entry(
                    tenant,
                    JournalEntryType.ACTION_FAILED,
                    f"action={action.action_id} reason={cmd.failure_reason}",
                    now,
                    system_attribution="worker",
                )
                await uow.journals.save(journal)
            await uow.attack_actions.save(action)
            await uow.commit()
            to_publish: list[Any] = [action]
            if journal is not None:
                to_publish.append(journal)
            await self._publish(to_publish)
            return self._attack_action_dto(action)

    async def record_action_output(self, cmd: RecordActionOutput) -> AttackActionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.output_hash, "output_hash", 64)
        validate_str(cmd.output_storage_ref, "output_storage_ref", 512)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            action = await uow.attack_actions.find_by_id(
                AttackActionId(cmd.action_id), tenant
            )
            if action is None:
                raise ApplicationNotFoundError("AttackAction", str(cmd.action_id))
            action.record_output_ref(
                tenant, ActionOutputRef(cmd.output_hash, cmd.output_storage_ref), now
            )
            await uow.attack_actions.save(action)
            await uow.commit()
            await self._publish([action])
            return self._attack_action_dto(action)

    async def get_attack_action(self, query: GetAttackAction) -> AttackActionDTO:
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            action = await uow.attack_actions.find_by_id(
                AttackActionId(query.action_id), tenant
            )
            if action is None:
                raise ApplicationNotFoundError("AttackAction", str(query.action_id))
            now = datetime.now(UTC)
            if not action.verify_integrity(now):
                await uow.attack_actions.save(action)
                await uow.commit()
                await self._publish([action])
            return self._attack_action_dto(action)

    async def list_attack_actions_by_operation(
        self, query: ListAttackActionsByOperation
    ) -> list[AttackActionDTO]:
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            actions = await uow.attack_actions.find_by_operation(
                OperationId(query.operation_id), tenant, limit=limit, offset=offset
            )
            return [self._attack_action_dto(a) for a in actions]

    # ── Phase 4: Workers ──────────────────────────────────────────────

    async def register_execution_worker(
        self, cmd: RegisterExecutionWorker
    ) -> ExecutionWorkerDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.signer_operator_id, "signer_operator_id")
        validate_str(cmd.signature, "signature", 4096)
        validate_str(cmd.network_zone, "network_zone", 128)
        if not cmd.techniques:
            raise ApplicationValidationError("techniques", "must not be empty")
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        manifest = SignedCapabilityManifest(
            techniques=frozenset(cmd.techniques),
            trust_level=WorkerTrustLevel(cmd.trust_level),
            signer_operator_id=OperatorId(cmd.signer_operator_id),
            signature=cmd.signature,
            signed_at=now,
        )
        worker = ExecutionWorker.register(
            tenant, WorkerType(cmd.worker_type), cmd.network_zone, manifest, now
        )
        async with self._uow_factory() as uow:
            await uow.workers.save(worker)
            await uow.commit()
            await self._publish([worker])
            return self._worker_dto(worker)

    async def decommission_execution_worker(
        self, cmd: DecommissionExecutionWorker
    ) -> ExecutionWorkerDTO:
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            worker = await uow.workers.find_by_id(
                ExecutionWorkerId(cmd.worker_id), tenant
            )
            if worker is None:
                raise ApplicationNotFoundError("ExecutionWorker", str(cmd.worker_id))
            worker.decommission(tenant, OperatorId(cmd.authority_operator_id), now)
            await uow.workers.save(worker)
            await uow.commit()
            await self._publish([worker])
            return self._worker_dto(worker)

    async def record_worker_heartbeat(
        self, cmd: RecordWorkerHeartbeat
    ) -> ExecutionWorkerDTO:
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            worker = await uow.workers.find_by_id(
                ExecutionWorkerId(cmd.worker_id), tenant
            )
            if worker is None:
                raise ApplicationNotFoundError("ExecutionWorker", str(cmd.worker_id))
            worker.record_heartbeat(
                tenant, WorkerHealthStatus(cmd.health_status), now
            )
            await uow.workers.save(worker)
            await uow.commit()
            await self._publish([worker])
            return self._worker_dto(worker)

    async def get_execution_worker(self, query: GetExecutionWorker) -> ExecutionWorkerDTO:
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            worker = await uow.workers.find_by_id(
                ExecutionWorkerId(query.worker_id), tenant
            )
            if worker is None:
                raise ApplicationNotFoundError("ExecutionWorker", str(query.worker_id))
            return self._worker_dto(worker)

    async def list_available_workers(
        self, query: ListAvailableWorkers
    ) -> list[ExecutionWorkerDTO]:
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            workers = await uow.workers.list_available(tenant, limit=limit, offset=offset)
            return [self._worker_dto(w) for w in workers]

    # ── Helpers ───────────────────────────────────────────────────────

    async def _sync_kill_switch_store(self, ks: KillSwitchState) -> None:
        if self._kill_switch_store_sync is None:
            return
        result = self._kill_switch_store_sync(ks)
        if hasattr(result, "__await__"):
            await result

    async def _journal_kill_switch(
        self,
        uow: IUnitOfWork,
        tenant: TenantId,
        scope: KillSwitchScope,
        scope_ref: Any,
        reason: str,
        now: datetime,
        attribution: OperatorId,
    ) -> None:
        if scope != KillSwitchScope.ENGAGEMENT:
            return
        engagement = EngagementId(scope_ref)
        journal = await uow.journals.find_by_engagement(engagement, tenant)
        if journal is None:
            journal = ExecutionJournal.create(tenant, engagement, now)
        journal.append_entry(
            tenant,
            JournalEntryType.KILL_SWITCH_TRIGGERED,
            f"scope={scope.value} ref={scope_ref} reason={reason}",
            now,
            attribution=attribution,
        )
        await uow.journals.save(journal)

    async def _journal_authorization_failure(
        self,
        uow: IUnitOfWork,
        tenant: TenantId,
        engagement: EngagementId,
        failure: AuthorizationFailureReason | None,
        cmd: AuthorizeAndStartAttackAction,
        now: datetime,
    ) -> None:
        journal = await uow.journals.find_by_engagement(engagement, tenant)
        if journal is None:
            journal = ExecutionJournal.create(tenant, engagement, now)
        if failure == AuthorizationFailureReason.SCOPE_VIOLATION:
            entry_type = JournalEntryType.SCOPE_VIOLATION_ATTEMPTED
        elif failure in (
            AuthorizationFailureReason.RATE_LIMIT_THROTTLED,
            AuthorizationFailureReason.RATE_LIMIT_FORBIDDEN,
        ):
            entry_type = JournalEntryType.SAFETY_CHECK_FAILED
        else:
            entry_type = JournalEntryType.SAFETY_CHECK_FAILED
        journal.append_entry(
            tenant,
            entry_type,
            (
                f"failure={failure.value if failure else 'unknown'} "
                f"step={cmd.step_id} target={cmd.target_id} technique={cmd.technique_id}"
            ),
            now,
            attribution=OperatorId(cmd.operator_id),
        )
        await uow.journals.save(journal)

    @staticmethod
    def _payload_failure_reason(
        check: PayloadDispatchCheck,
    ) -> AuthorizationFailureReason | None:
        if check.approved and check.hash_ok:
            return None
        if check.failure_reason == AuthorizationFailureReason.PAYLOAD_REVOKED.value:
            return AuthorizationFailureReason.PAYLOAD_REVOKED
        if check.failure_reason == AuthorizationFailureReason.PAYLOAD_HASH_MISMATCH.value:
            return AuthorizationFailureReason.PAYLOAD_HASH_MISMATCH
        if not check.hash_ok:
            return AuthorizationFailureReason.PAYLOAD_HASH_MISMATCH
        return AuthorizationFailureReason.PAYLOAD_NOT_APPROVED

    async def _publish(self, aggregates: list[Any]) -> None:
        events = []
        for a in aggregates:
            if hasattr(a, "pop_events"):
                events.extend(a.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    @staticmethod
    def _parse_scope(scope: str) -> KillSwitchScope:
        try:
            return KillSwitchScope(scope)
        except ValueError as exc:
            raise ApplicationValidationError("scope", f"invalid scope: {scope}") from exc

    @staticmethod
    def _kill_switch_dto(ks: KillSwitchState) -> KillSwitchDTO:
        return KillSwitchDTO(
            kill_switch_id=str(ks.kill_switch_id),
            tenant_id=str(ks.tenant_id),
            scope=ks.scope.value,
            scope_ref=str(ks.scope_ref),
            armed_state=ks.armed_state.value,
            trigger_authority=(
                str(ks.trigger_authority.operator_id) if ks.trigger_authority else None
            ),
            trigger_reason=ks.trigger_reason.value if ks.trigger_reason else None,
            trigger_hash=ks.trigger_hash.value if ks.trigger_hash else None,
            release_authority=(
                str(ks.release_authority.operator_id) if ks.release_authority else None
            ),
            version=ks.version,
            created_at=ks.created_at.isoformat(),
            updated_at=ks.updated_at.isoformat(),
        )

    @staticmethod
    def _journal_dto(journal: ExecutionJournal) -> JournalDTO:
        entries = tuple(
            JournalEntryDTO(
                entry_id=str(e.entry_id),
                entry_type=e.entry_type.value,
                sequence_number=e.sequence_number,
                entry_hash=e.entry_hash,
                previous_entry_hash=e.previous_entry_hash,
                content=e.content,
                occurred_at=e.occurred_at.isoformat(),
            )
            for e in journal.entries
        )
        return JournalDTO(
            journal_id=str(journal.journal_id),
            tenant_id=str(journal.tenant_id),
            engagement_id=str(journal.engagement_id),
            entry_count=len(journal.entries),
            entries=entries,
            version=journal.version,
            created_at=journal.created_at.isoformat(),
            updated_at=journal.updated_at.isoformat(),
        )

    @staticmethod
    def _attack_action_dto(action: AttackAction) -> AttackActionDTO:
        return AttackActionDTO(
            action_id=str(action.action_id),
            tenant_id=str(action.tenant_id),
            engagement_id=str(action.engagement_id),
            operation_id=str(action.operation_id),
            step_id=str(action.step_ref.step_id),
            target_id=str(action.target_ref.target_id),
            technique_id=action.technique_ref.technique_id,
            impact_ceiling=action.technique_ref.impact_ceiling.value,
            state=action.state.value,
            action_hash=action.action_hash.value,
            worker_id=(
                str(action.worker_ref.worker_id) if action.worker_ref else None
            ),
            operator_id=str(action.operator_ref.operator_id),
            execution_timestamp=action.execution_timestamp.isoformat(),
            completion_timestamp=(
                action.completion_timestamp.isoformat()
                if action.completion_timestamp
                else None
            ),
            output_hash=action.output_ref.output_hash if action.output_ref else None,
            version=action.version,
        )

    @staticmethod
    def _worker_dto(worker: ExecutionWorker) -> ExecutionWorkerDTO:
        return ExecutionWorkerDTO(
            worker_id=str(worker.worker_id),
            tenant_id=str(worker.tenant_id),
            worker_type=worker.worker_type.value,
            trust_level=worker.trust_level.value,
            health_status=worker.health_status.value,
            network_zone=worker.network_zone,
            capabilities=tuple(sorted(worker.capabilities)),
            manifest_hash=worker.manifest_hash,
            last_heartbeat_at=(
                worker.last_heartbeat_at.isoformat() if worker.last_heartbeat_at else None
            ),
            version=worker.version,
        )

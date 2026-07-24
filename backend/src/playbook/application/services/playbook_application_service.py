"""CQRS application service for playbook BC."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from playbook.application._auth import require_any, require_role
from playbook.application.commands.playbook_commands import (
    ActivateKillSwitch,
    ApprovePlaybook,
    CreatePlaybook,
    DeprecatePlaybook,
    PublishPlaybookVersion,
    ResetKillSwitch,
    RunPlaybookDryRun,
    SubmitPlaybookForApproval,
    UpdateAutomationPolicy,
)
from playbook.application.dtos.playbook_dtos import (
    AutomationPolicyDTO,
    PlaybookDTO,
    PlaybookTestResultDTO,
    PlaybookVersionDTO,
)
from playbook.application.exceptions import ApplicationNotFoundError
from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.events.playbook_events import PlaybookTestCompleted
from playbook.domain.exceptions.domain_exceptions import (
    DryRunHashMismatch,
    DryRunNotPassed,
    DryRunRequired,
)
from playbook.domain.services.kill_switch_service import KillSwitchService
from playbook.domain.services.playbook_approval_service import PlaybookApprovalService
from playbook.domain.services.playbook_authorization_service import PlaybookAuthorizationService
from playbook.domain.services.playbook_content_hash_service import PlaybookContentHashService
from playbook.domain.services.playbook_dry_run_service import PlaybookDryRunService
from playbook.domain.services.playbook_lifecycle_service import PlaybookLifecycleService
from playbook.domain.value_objects.definitions import (
    ActionStepDefinition,
    RollbackDefinition,
    TargetSelectorExpression,
    TriggerCondition,
)
from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    TestOutcome,
    TriggerSourceContext,
)
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    TenantId,
)


class PlaybookApplicationService:
    def __init__(
        self,
        playbooks: Any,
        versions: Any,
        tests: Any,
        policies: Any,
        event_sink: list[Any] | None = None,
        kill_switch_log: list[dict[str, Any]] | None = None,
    ) -> None:
        self._playbooks = playbooks
        self._versions = versions
        self._tests = tests
        self._policies = policies
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._kill_log: list[dict[str, Any]] = (
            kill_switch_log if kill_switch_log is not None else []
        )
        self._authz = PlaybookAuthorizationService()
        self._hash = PlaybookContentHashService()
        self._dry = PlaybookDryRunService()
        self._lifecycle = PlaybookLifecycleService()
        self._approval = PlaybookApprovalService()
        self._kill = KillSwitchService()

    def _tenant(self, value: TenantId) -> TenantId:
        if isinstance(value, TenantId):
            return value
        return TenantId.from_string(str(value))

    def _to_dto(self, pb: Playbook) -> PlaybookDTO:
        return PlaybookDTO(
            playbook_id=str(pb.playbook_id),
            tenant_id=str(pb.tenant_id),
            name=pb.name,
            description=pb.description,
            status=pb.status.value,
            current_version_number=pb.current_version_number,
            max_impact_level=pb.max_impact_level.value,
            created_by=pb.created_by,
            approved_by=[a.approved_by for a in pb.approved_by],
        )

    @staticmethod
    def _as_int(value: object, default: int) -> int:
        if value is None:
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float | str):
            return int(value)
        return default

    @staticmethod
    def _as_params(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return {str(k): v for k, v in value.items()}
        return {}

    def _parse_steps(self, raw: list[dict[str, object]]) -> list[ActionStepDefinition]:
        steps: list[ActionStepDefinition] = []
        for item in raw:
            rb_raw = item.get("rollback_definition")
            rollback = None
            if isinstance(rb_raw, dict):
                rollback = RollbackDefinition(
                    str(rb_raw["rollback_action_type"]),
                    ConnectorType(str(rb_raw["rollback_connector_type"])),
                    bool(rb_raw.get("is_reversible", True)),
                    self._as_int(rb_raw.get("max_rollback_window_hours"), 24),
                )
            steps.append(
                ActionStepDefinition(
                    self._as_int(item["step_number"], 0),
                    str(item["action_type"]),
                    ConnectorType(str(item["connector_type"])),
                    TargetSelectorExpression(str(item.get("target_selector", "*"))),
                    self._as_params(item.get("parameters")),
                    ActionImpactLevel(str(item["impact_level"])),
                    rollback,
                    self._as_int(item.get("max_execution_seconds"), 120),
                )
            )
        return steps

    def _parse_triggers(self, raw: list[dict[str, object]]) -> list[TriggerCondition]:
        out: list[TriggerCondition] = []
        for item in raw:
            tags = item.get("asset_tag_filter")
            tag_list = [str(t) for t in tags] if isinstance(tags, list) else None
            out.append(
                TriggerCondition(
                    TriggerSourceContext(str(item["source_context"])),
                    str(item["trigger_type"]),
                    str(item["severity_threshold"]) if item.get("severity_threshold") else None,
                    tag_list,
                    self._as_int(item.get("rate_limit_window_seconds"), 300),
                    self._as_int(item.get("rate_limit_max_invocations"), 1),
                )
            )
        return out

    async def create(self, cmd: CreatePlaybook) -> PlaybookDTO:
        require_any(cmd.roles, "playbook:engineer")
        tenant = self._tenant(cmd.tenant_id)
        pb = Playbook.create(tenant, cmd.name, cmd.description, cmd.created_by)
        await self._playbooks.save(pb, tenant)
        self._events.extend(pb.pop_events())
        return self._to_dto(pb)

    async def publish_version(self, cmd: PublishPlaybookVersion) -> PlaybookVersionDTO:
        require_any(cmd.roles, "playbook:engineer")
        tenant = self._tenant(cmd.tenant_id)
        pid = PlaybookId(cmd.playbook_id)
        pb = await self._playbooks.get(pid, tenant)
        if pb is None:
            raise ApplicationNotFoundError("playbook not found")
        latest = await self._versions.get_latest(pid, tenant)
        next_num = (latest.version_number + 1) if latest else 1
        steps = self._parse_steps(cmd.action_steps)
        triggers = self._parse_triggers(cmd.trigger_configs)
        version = PlaybookVersion.create_draft(tenant, pid, next_num, steps, triggers)
        version.publish(cmd.published_by)
        pb.set_current_version(next_num)
        pb.set_max_impact(self._lifecycle.max_impact(steps))
        await self._versions.save(version, tenant)
        await self._playbooks.save(pb, tenant)
        self._events.extend(version.pop_events())
        return PlaybookVersionDTO(
            str(version.version_id),
            str(pid),
            version.version_number,
            version.status.value,
            version.content_hash,
            len(version.action_steps),
        )

    async def submit_for_approval(self, cmd: SubmitPlaybookForApproval) -> PlaybookDTO:
        require_any(cmd.roles, "playbook:engineer")
        tenant = self._tenant(cmd.tenant_id)
        pid = PlaybookId(cmd.playbook_id)
        pb = await self._playbooks.get(pid, tenant)
        if pb is None:
            raise ApplicationNotFoundError("playbook not found")
        version = await self._versions.get(pid, cmd.version_number, tenant)
        if version is None:
            raise ApplicationNotFoundError("version not found")
        pb.submit_for_approval(tenant)
        await self._playbooks.save(pb, tenant)
        return self._to_dto(pb)

    async def approve(self, cmd: ApprovePlaybook) -> PlaybookDTO:
        tenant = self._tenant(cmd.tenant_id)
        pid = PlaybookId(cmd.playbook_id)
        pb = await self._playbooks.get(pid, tenant)
        if pb is None:
            raise ApplicationNotFoundError("playbook not found")
        version = await self._versions.get(pid, cmd.version_number, tenant)
        if version is None:
            raise ApplicationNotFoundError("version not found")
        latest_test = await self._tests.find_latest_for_version(pid, version.version_id, tenant)
        if latest_test is None:
            raise DryRunRequired("playbook version must pass dry-run before approval")
        if latest_test.content_hash_at_test != version.content_hash:
            raise DryRunHashMismatch("playbook content changed since last dry-run; re-run required")
        if latest_test.outcome != TestOutcome.PASSED:
            raise DryRunNotPassed(f"last dry-run outcome: {latest_test.outcome.value}")
        self._authz.assert_approval_authorized(
            pb.max_impact_level, cmd.roles, existing_approver_count=len(pb.approved_by)
        )
        # CRITICAL dual: ensure complementary roles across approvers
        if pb.max_impact_level.value == "CRITICAL" and pb.approved_by:
            roles_so_far = {a.role for a in pb.approved_by}
            roles_so_far.add(cmd.approved_by_role)
            if not ({"soc:commander", "incident:ciso"} <= roles_so_far):
                # still allow recording; final approval only when quorum + complementary
                pass
        quorum = self._approval.quorum_for(pb.max_impact_level)
        pb.record_approval(tenant, cmd.approved_by, cmd.approved_by_role, quorum_required=quorum)
        if pb.status.value == "APPROVED" and pb.max_impact_level.value == "CRITICAL":
            roles_used = {a.role for a in pb.approved_by}
            if not ({"soc:commander", "incident:ciso"} <= roles_used):
                # roll back approval status if complementary roles missing
                from playbook.domain.value_objects.enums import PlaybookStatus

                pb.status = PlaybookStatus.UNDER_REVIEW
                if len(pb.approved_by) >= quorum:
                    # keep approvals but not APPROVED
                    pass
        await self._playbooks.save(pb, tenant)
        self._events.extend(pb.pop_events())
        return self._to_dto(pb)

    async def deprecate(self, cmd: DeprecatePlaybook) -> PlaybookDTO:
        require_any(cmd.roles, "soc:commander", "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        pid = PlaybookId(cmd.playbook_id)
        pb = await self._playbooks.get(pid, tenant)
        if pb is None:
            raise ApplicationNotFoundError("playbook not found")
        pb.deprecate(tenant, cmd.deprecated_by, cmd.reason)
        await self._playbooks.save(pb, tenant)
        self._events.extend(pb.pop_events())
        return self._to_dto(pb)

    async def dry_run(self, cmd: RunPlaybookDryRun) -> PlaybookTestResultDTO:
        require_any(cmd.roles, "playbook:engineer")
        tenant = self._tenant(cmd.tenant_id)
        pid = PlaybookId(cmd.playbook_id)
        pb = await self._playbooks.get(pid, tenant)
        if pb is None:
            raise ApplicationNotFoundError("playbook not found")
        latest = await self._versions.get_latest(pid, tenant)
        if latest is None or latest.version_id.value != cmd.version_id:
            # allow explicit version lookup via latest versions scan
            version = None
            for n in range(1, pb.current_version_number + 1):
                v = await self._versions.get(pid, n, tenant)
                if v and v.version_id.value == cmd.version_id:
                    version = v
                    break
            if version is None:
                raise ApplicationNotFoundError("version not found")
        else:
            version = latest
        result = self._dry.run(version)
        content_hash = version.content_hash or self._hash.compute(version)
        now = datetime.now(UTC)
        record = PlaybookTestResult.create(
            tenant,
            pid,
            version.version_id,
            content_hash,
            result.outcome,
            result.steps_tested,
            result.steps_passed,
            result.coverage_paths,
            cmd.executed_by,
            now,
            result.duration_ms,
        )
        await self._tests.append(record, tenant)
        self._events.append(
            PlaybookTestCompleted(
                tenant_id=str(tenant),
                aggregate_id=str(record.test_id),
                playbook_id=str(pid),
                test_id=str(record.test_id),
                version_id=str(version.version_id),
                content_hash_at_test=content_hash,
                outcome=result.outcome.value,
                steps_tested=result.steps_tested,
                steps_passed=result.steps_passed,
                executed_at=now.isoformat(),
            )
        )
        return PlaybookTestResultDTO(
            str(record.test_id),
            str(pid),
            str(version.version_id),
            content_hash,
            result.outcome.value,
            result.steps_tested,
            result.steps_passed,
        )

    async def activate_kill_switch(self, cmd: ActivateKillSwitch) -> AutomationPolicyDTO:
        require_role(cmd.roles, "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        policy = await self._policies.get_or_create_default(tenant)
        self._kill.activate(policy, cmd.activated_by, cmd.reason)
        await self._policies.save(policy, tenant)
        events = policy.pop_events()
        self._events.extend(events)
        self._kill_log.append(
            {
                "tenant_id": str(tenant),
                "event_type": "ACTIVATED",
                "actor": cmd.activated_by,
                "reason": cmd.reason,
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )
        return self._policy_dto(policy)

    async def reset_kill_switch(self, cmd: ResetKillSwitch) -> AutomationPolicyDTO:
        require_role(cmd.roles, "incident:ciso")
        tenant = self._tenant(cmd.tenant_id)
        policy = await self._policies.get_or_create_default(tenant)
        self._kill.reset(policy, cmd.reset_by)
        await self._policies.save(policy, tenant)
        self._events.extend(policy.pop_events())
        self._kill_log.append(
            {
                "tenant_id": str(tenant),
                "event_type": "RESET",
                "actor": cmd.reset_by,
                "reason": "",
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )
        return self._policy_dto(policy)

    async def update_policy(self, cmd: UpdateAutomationPolicy) -> AutomationPolicyDTO:
        require_any(cmd.roles, "incident:ciso", "soc:commander")
        tenant = self._tenant(cmd.tenant_id)
        policy = await self._policies.get_or_create_default(tenant)
        policy.update_budgets(
            max_concurrent_executions=cmd.max_concurrent_executions,
            max_actions_per_hour=cmd.max_actions_per_hour,
        )
        await self._policies.save(policy, tenant)
        return self._policy_dto(policy)

    async def get_playbook(
        self, tenant_id: TenantId, playbook_id: UUID, roles: tuple[str, ...]
    ) -> PlaybookDTO:
        require_any(
            roles, "playbook:analyst", "playbook:engineer", "soc:commander", "incident:ciso"
        )
        tenant = self._tenant(tenant_id)
        pb = await self._playbooks.get(PlaybookId(playbook_id), tenant)
        if pb is None:
            raise ApplicationNotFoundError("playbook not found")
        return self._to_dto(pb)

    async def list_playbooks(
        self,
        tenant_id: TenantId,
        roles: tuple[str, ...],
        *,
        status_filter: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> list[PlaybookDTO]:
        require_any(
            roles, "playbook:analyst", "playbook:engineer", "soc:commander", "incident:ciso"
        )
        rows = await self._playbooks.list(
            self._tenant(tenant_id), status_filter=status_filter, page=page, page_size=page_size
        )
        return [self._to_dto(r) for r in rows]

    async def get_policy(self, tenant_id: TenantId, roles: tuple[str, ...]) -> AutomationPolicyDTO:
        require_any(roles, "playbook:analyst", "soc:commander", "incident:ciso")
        policy = await self._policies.get_or_create_default(self._tenant(tenant_id))
        return self._policy_dto(policy)

    def _policy_dto(self, policy: Any) -> AutomationPolicyDTO:
        return AutomationPolicyDTO(
            str(policy.tenant_id),
            policy.kill_switch_state.value,
            policy.kill_switch_triggered_by,
            policy.max_concurrent_executions,
            policy.max_actions_per_hour,
        )

    async def get_version(
        self, tenant_id: TenantId, playbook_id: UUID, version_number: int, roles: tuple[str, ...]
    ) -> PlaybookVersionDTO:
        require_any(roles, "playbook:analyst", "playbook:engineer")
        tenant = self._tenant(tenant_id)
        version = await self._versions.get(PlaybookId(playbook_id), version_number, tenant)
        if version is None:
            raise ApplicationNotFoundError("version not found")
        return PlaybookVersionDTO(
            str(version.version_id),
            str(playbook_id),
            version.version_number,
            version.status.value,
            version.content_hash,
            len(version.action_steps),
        )

"""PostgreSQL repositories for playbook.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts.

Schema note: playbook_trigger_configs is keyed by playbook_id (migration
0117), not version_id, even though PlaybookVersion embeds trigger_configs
as version-scoped domain state — the trigger set is actually shared across
a playbook's versions at the persistence layer. Saving any version's
trigger_configs replaces the playbook-wide set.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select

from playbook.domain.aggregates.automation_policy import AutomationPolicy
from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.repositories.i_playbook_repositories import (
    IAutomationPolicyRepository,
    IPlaybookRepository,
    IPlaybookTestResultRepository,
    IPlaybookVersionRepository,
)
from playbook.domain.value_objects.definitions import (
    ActionStepDefinition,
    ApprovalRecord,
    RollbackDefinition,
    TargetSelectorExpression,
    TriggerCondition,
)
from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    KillSwitchState,
    PlaybookStatus,
    TestOutcome,
    TriggerSourceContext,
    VersionStatus,
)
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookTestResultId,
    PlaybookVersionId,
    TenantId,
)
from playbook.infrastructure.persistence.models.orm_models import (
    AutomationPolicyModel,
    PlaybookActionStepModel,
    PlaybookModel,
    PlaybookTestResultModel,
    PlaybookTriggerConfigModel,
    PlaybookVersionModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ── Playbook ─────────────────────────────────────────────────────────────────


def _playbook_to_row(playbook: Playbook) -> PlaybookModel:
    return PlaybookModel(
        id=playbook.playbook_id.value,
        tenant_id=playbook.tenant_id.value,
        name=playbook.name,
        description=playbook.description,
        status=playbook.status.value,
        current_version_number=playbook.current_version_number,
        max_impact_level=playbook.max_impact_level.value,
        created_by=playbook.created_by,
        created_at=playbook.created_at,
        # No updated_at on the domain aggregate (it tracks an incrementing
        # `version` counter instead) — record actual persistence time.
        updated_at=datetime.now(UTC),
        approved_by_json=[
            {"approved_by": a.approved_by, "approved_at": a.approved_at.isoformat(), "role": a.role}
            for a in playbook.approved_by
        ],
    )


def _row_to_playbook(row: PlaybookModel) -> Playbook:
    from datetime import datetime as _dt

    approved_by = [
        ApprovalRecord(
            approved_by=str(a["approved_by"]),
            approved_at=_dt.fromisoformat(str(a["approved_at"])),
            role=str(a["role"]),
        )
        for a in (row.approved_by_json or [])
    ]
    return Playbook(
        playbook_id=PlaybookId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        name=row.name,
        description=row.description,
        status=PlaybookStatus(row.status),
        current_version_number=row.current_version_number,
        max_impact_level=ActionImpactLevel(row.max_impact_level),
        created_by=row.created_by,
        created_at=row.created_at,
        approved_by=approved_by,
    )


class PgPlaybookRepository(IPlaybookRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, playbook: Playbook, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_playbook_to_row(playbook))
            await session.commit()

    async def get(self, playbook_id: PlaybookId, tenant_id: TenantId) -> Playbook | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PlaybookModel).where(
                        PlaybookModel.tenant_id == tenant_id.value,
                        PlaybookModel.id == playbook_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_playbook(row) if row is not None else None

    async def find_approved_for_trigger(
        self, tenant_id: TenantId, source_context: TriggerSourceContext
    ) -> list[Playbook]:
        # in-memory repo ignores source_context too — matched for parity.
        del source_context
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(PlaybookModel).where(
                        PlaybookModel.tenant_id == tenant_id.value,
                        PlaybookModel.status == PlaybookStatus.APPROVED.value,
                    )
                )
            ).scalars().all()
            return [_row_to_playbook(r) for r in rows]

    async def list(
        self, tenant_id: TenantId, *, status_filter: str | None, page: int, page_size: int
    ) -> list[Playbook]:
        async with self._session_factory() as session:
            stmt = select(PlaybookModel).where(PlaybookModel.tenant_id == tenant_id.value)
            if status_filter:
                stmt = stmt.where(PlaybookModel.status == status_filter)
            stmt = stmt.order_by(PlaybookModel.created_at).offset((page - 1) * page_size).limit(
                page_size
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_playbook(r) for r in rows]


# ── PlaybookVersion ──────────────────────────────────────────────────────────


def _action_step_to_dict(step: ActionStepDefinition) -> dict[str, object]:
    return {
        "step_number": step.step_number,
        "action_type": step.action_type,
        "connector_type": step.connector_type.value,
        "target_selector": step.target_selector.expression,
        "parameters": dict(step.parameters),
        "impact_level": step.impact_level.value,
        "rollback_definition": (
            {
                "rollback_action_type": step.rollback_definition.rollback_action_type,
                "rollback_connector_type": step.rollback_definition.rollback_connector_type.value,
                "is_reversible": step.rollback_definition.is_reversible,
                "max_rollback_window_hours": step.rollback_definition.max_rollback_window_hours,
            }
            if step.rollback_definition
            else None
        ),
        "max_execution_seconds": step.max_execution_seconds,
    }


class PgPlaybookVersionRepository(IPlaybookVersionRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _load_children(
        self, session: AsyncSession, tenant_id: TenantId, version_row: PlaybookVersionModel
    ) -> tuple[list[ActionStepDefinition], list[TriggerCondition]]:
        step_rows = (
            await session.execute(
                select(PlaybookActionStepModel)
                .where(
                    PlaybookActionStepModel.tenant_id == tenant_id.value,
                    PlaybookActionStepModel.version_id == version_row.id,
                )
                .order_by(PlaybookActionStepModel.step_number)
            )
        ).scalars().all()
        action_steps = [
            ActionStepDefinition(
                step_number=s.step_number,
                action_type=s.action_type,
                connector_type=ConnectorType(s.connector_type),
                target_selector=TargetSelectorExpression(s.target_selector_expr),
                parameters=dict(s.parameters),
                impact_level=ActionImpactLevel(s.impact_level),
                rollback_definition=(
                    RollbackDefinition(
                        rollback_action_type=s.rollback_definition["rollback_action_type"],
                        rollback_connector_type=ConnectorType(
                            s.rollback_definition["rollback_connector_type"]
                        ),
                        is_reversible=s.rollback_definition["is_reversible"],
                        max_rollback_window_hours=s.rollback_definition[
                            "max_rollback_window_hours"
                        ],
                    )
                    if s.rollback_definition
                    else None
                ),
                max_execution_seconds=s.max_execution_seconds,
            )
            for s in step_rows
        ]

        trigger_rows = (
            await session.execute(
                select(PlaybookTriggerConfigModel).where(
                    PlaybookTriggerConfigModel.tenant_id == tenant_id.value,
                    PlaybookTriggerConfigModel.playbook_id == version_row.playbook_id,
                )
            )
        ).scalars().all()
        trigger_configs = [
            TriggerCondition(
                source_context=TriggerSourceContext(t.source_context),
                trigger_type=t.trigger_type,
                severity_threshold=t.severity_threshold,
                asset_tag_filter=list(t.asset_tag_filter) if t.asset_tag_filter else None,
                rate_limit_window_seconds=t.rate_limit_window_seconds,
                rate_limit_max_invocations=t.rate_limit_max_invocations,
            )
            for t in trigger_rows
        ]
        return action_steps, trigger_configs

    async def _to_domain(
        self, session: AsyncSession, tenant_id: TenantId, row: PlaybookVersionModel
    ) -> PlaybookVersion:
        action_steps, trigger_configs = await self._load_children(session, tenant_id, row)
        return PlaybookVersion(
            version_id=PlaybookVersionId(row.id),
            tenant_id=TenantId.from_uuid(row.tenant_id),
            playbook_id=PlaybookId(row.playbook_id),
            version_number=row.version_number,
            status=VersionStatus(row.status),
            action_steps=action_steps,
            trigger_configs=trigger_configs,
            content_hash=row.content_hash,
            published_by=row.published_by,
            published_at=row.published_at,
        )

    async def save(self, version: PlaybookVersion, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            existing_created_at = (
                await session.execute(
                    select(PlaybookVersionModel.created_at).where(
                        PlaybookVersionModel.id == version.version_id.value
                    )
                )
            ).scalar_one_or_none()

            row = PlaybookVersionModel(
                id=version.version_id.value,
                tenant_id=tenant_id.value,
                playbook_id=version.playbook_id.value,
                version_number=version.version_number,
                status=version.status.value,
                content_hash=version.content_hash,
                published_by=version.published_by,
                published_at=version.published_at,
                # No created_at on the domain aggregate — preserve the
                # original row value across updates (e.g. publish()) rather
                # than resetting it on every save.
                created_at=existing_created_at or datetime.now(UTC),
            )
            if existing_created_at is None:
                session.add(row)
            else:
                await session.merge(row)

            await session.execute(
                delete(PlaybookActionStepModel).where(
                    PlaybookActionStepModel.tenant_id == tenant_id.value,
                    PlaybookActionStepModel.version_id == version.version_id.value,
                )
            )
            for step in version.action_steps:
                d = _action_step_to_dict(step)
                session.add(
                    PlaybookActionStepModel(
                        id=uuid4(),
                        tenant_id=tenant_id.value,
                        version_id=version.version_id.value,
                        step_number=d["step_number"],
                        action_type=d["action_type"],
                        connector_type=d["connector_type"],
                        target_selector_expr=d["target_selector"],
                        parameters=d["parameters"],
                        impact_level=d["impact_level"],
                        rollback_definition=d["rollback_definition"],
                        max_execution_seconds=d["max_execution_seconds"],
                    )
                )

            await session.execute(
                delete(PlaybookTriggerConfigModel).where(
                    PlaybookTriggerConfigModel.tenant_id == tenant_id.value,
                    PlaybookTriggerConfigModel.playbook_id == version.playbook_id.value,
                )
            )
            for trigger in version.trigger_configs:
                session.add(
                    PlaybookTriggerConfigModel(
                        id=uuid4(),
                        tenant_id=tenant_id.value,
                        playbook_id=version.playbook_id.value,
                        source_context=trigger.source_context.value,
                        trigger_type=trigger.trigger_type,
                        severity_threshold=trigger.severity_threshold,
                        asset_tag_filter=trigger.asset_tag_filter,
                        rate_limit_window_seconds=trigger.rate_limit_window_seconds,
                        rate_limit_max_invocations=trigger.rate_limit_max_invocations,
                    )
                )

            await session.commit()

    async def get(
        self, playbook_id: PlaybookId, version_number: int, tenant_id: TenantId
    ) -> PlaybookVersion | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PlaybookVersionModel).where(
                        PlaybookVersionModel.tenant_id == tenant_id.value,
                        PlaybookVersionModel.playbook_id == playbook_id.value,
                        PlaybookVersionModel.version_number == version_number,
                    )
                )
            ).scalar_one_or_none()
            return await self._to_domain(session, tenant_id, row) if row is not None else None

    async def get_latest(
        self, playbook_id: PlaybookId, tenant_id: TenantId
    ) -> PlaybookVersion | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PlaybookVersionModel)
                    .where(
                        PlaybookVersionModel.tenant_id == tenant_id.value,
                        PlaybookVersionModel.playbook_id == playbook_id.value,
                    )
                    .order_by(PlaybookVersionModel.version_number.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            return await self._to_domain(session, tenant_id, row) if row is not None else None


# ── PlaybookTestResult (append-only) ─────────────────────────────────────────


class PgPlaybookTestResultRepository(IPlaybookTestResultRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(self, result: PlaybookTestResult, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            session.add(
                PlaybookTestResultModel(
                    id=result.test_id.value,
                    tenant_id=tenant_id.value,
                    playbook_id=result.playbook_id.value,
                    version_id=result.version_id.value,
                    content_hash_at_test=result.content_hash_at_test,
                    outcome=result.outcome.value,
                    steps_tested=result.steps_tested,
                    steps_passed=result.steps_passed,
                    coverage_paths=list(result.coverage_paths),
                    executed_by=result.executed_by,
                    executed_at=result.executed_at,
                    duration_ms=result.duration_ms,
                )
            )
            await session.commit()

    async def find_latest_for_version(
        self, playbook_id: PlaybookId, version_id: PlaybookVersionId, tenant_id: TenantId
    ) -> PlaybookTestResult | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(PlaybookTestResultModel)
                    .where(
                        PlaybookTestResultModel.tenant_id == tenant_id.value,
                        PlaybookTestResultModel.playbook_id == playbook_id.value,
                        PlaybookTestResultModel.version_id == version_id.value,
                    )
                    .order_by(PlaybookTestResultModel.executed_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            return PlaybookTestResult(
                test_id=PlaybookTestResultId(row.id),
                tenant_id=TenantId.from_uuid(row.tenant_id),
                playbook_id=PlaybookId(row.playbook_id),
                version_id=PlaybookVersionId(row.version_id),
                content_hash_at_test=row.content_hash_at_test,
                outcome=TestOutcome(row.outcome),
                steps_tested=row.steps_tested,
                steps_passed=row.steps_passed,
                coverage_paths=list(row.coverage_paths),
                executed_by=row.executed_by,
                executed_at=row.executed_at,
                duration_ms=row.duration_ms,
            )


# ── AutomationPolicy ─────────────────────────────────────────────────────────


class PgAutomationPolicyRepository(IAutomationPolicyRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_or_create_default(self, tenant_id: TenantId) -> AutomationPolicy:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AutomationPolicyModel).where(
                        AutomationPolicyModel.tenant_id == tenant_id.value
                    )
                )
            ).scalar_one_or_none()
            if row is not None:
                return _row_to_policy(row)

            policy = AutomationPolicy.default(tenant_id)
            session.add(_policy_to_row(policy))
            await session.commit()
            return policy

    async def save(self, policy: AutomationPolicy, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_policy_to_row(policy))
            await session.commit()


def _policy_to_row(policy: AutomationPolicy) -> AutomationPolicyModel:
    return AutomationPolicyModel(
        tenant_id=policy.tenant_id.value,
        kill_switch_state=policy.kill_switch_state.value,
        kill_switch_triggered_at=policy.kill_switch_triggered_at,
        kill_switch_triggered_by=policy.kill_switch_triggered_by,
        max_concurrent_executions=policy.max_concurrent_executions,
        max_actions_per_hour=policy.max_actions_per_hour,
        allowed_connector_types=(
            [c.value for c in policy.allowed_connector_types]
            if policy.allowed_connector_types
            else None
        ),
        updated_at=policy.updated_at,
    )


def _row_to_policy(row: AutomationPolicyModel) -> AutomationPolicy:
    return AutomationPolicy(
        tenant_id=TenantId.from_uuid(row.tenant_id),
        kill_switch_state=KillSwitchState(row.kill_switch_state),
        kill_switch_triggered_at=row.kill_switch_triggered_at,
        kill_switch_triggered_by=row.kill_switch_triggered_by,
        max_concurrent_executions=row.max_concurrent_executions,
        max_actions_per_hour=row.max_actions_per_hour,
        allowed_connector_types=(
            [ConnectorType(c) for c in row.allowed_connector_types]
            if row.allowed_connector_types
            else None
        ),
        updated_at=row.updated_at,
    )

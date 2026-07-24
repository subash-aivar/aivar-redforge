"""PgCampaignRepository — SQLAlchemy implementation with optimistic locking."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select, update

from campaign.domain.aggregates.campaign import Campaign
from campaign.domain.entities.campaign_entities import (
    CampaignApproval,
    CampaignObjective,
    CampaignSchedule,
)
from campaign.domain.exceptions.domain_exceptions import OptimisticLockConflict
from campaign.domain.repositories.i_campaign_repository import ICampaignRepository
from campaign.domain.value_objects.campaign_vos import (
    ApprovalPolicy,
    ApprovalRecord,
    CampaignSafetyPolicyVO,
    EngagementRef,
    ObjectiveEvaluationCriteria,
    TargetSelectionRule,
)
from campaign.domain.value_objects.enums import (
    CampaignClassification,
    CampaignKind,
    CampaignState,
    ObjectiveState,
    ObjectiveType,
    QuorumType,
)
from campaign.domain.value_objects.identifiers import (
    CampaignApprovalId,
    CampaignId,
    CampaignObjectiveId,
    TenantId,
)
from campaign.infrastructure.persistence.models.campaign_models import (
    CampaignApprovalModel,
    CampaignModel,
    CampaignObjectiveModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _safety_policy_to_json(policy: CampaignSafetyPolicyVO) -> dict[str, Any]:
    return {
        "max_concurrent_actions": policy.max_concurrent_actions,
        "auto_abort_on_detection": policy.auto_abort_on_detection,
        "auto_abort_on_objective_failure": policy.auto_abort_on_objective_failure,
        "blast_radius_ceiling": policy.blast_radius_ceiling,
    }


def _safety_policy_from_json(data: dict[str, Any]) -> CampaignSafetyPolicyVO:
    return CampaignSafetyPolicyVO(
        max_concurrent_actions=int(data.get("max_concurrent_actions", 10)),
        auto_abort_on_detection=bool(data.get("auto_abort_on_detection", False)),
        auto_abort_on_objective_failure=bool(data.get("auto_abort_on_objective_failure", False)),
        blast_radius_ceiling=str(data.get("blast_radius_ceiling", "Probe")),
    )


def _approval_policy_to_json(policy: ApprovalPolicy) -> dict[str, Any]:
    return {
        "required_approver_count": policy.required_approver_count,
        "required_approver_roles": list(policy.required_approver_roles),
        "quorum_type": policy.quorum_type,
    }


def _approval_policy_from_json(data: dict[str, Any]) -> ApprovalPolicy:
    return ApprovalPolicy(
        required_approver_count=int(data.get("required_approver_count", 1)),
        required_approver_roles=list(data.get("required_approver_roles") or []),
        quorum_type=str(data.get("quorum_type", QuorumType.UNANIMOUS)),
    )


def _schedule_to_json(schedule: CampaignSchedule | None) -> dict[str, Any] | None:
    if schedule is None:
        return None
    return {
        "cron_expression": schedule.cron_expression,
        "execution_window_hours": schedule.execution_window_hours,
        "max_consecutive_failures": schedule.max_consecutive_failures,
        "blackout_periods": list(schedule.blackout_periods),
        "consecutive_failure_count": schedule.consecutive_failure_count,
        "scheduler_job_id": schedule.scheduler_job_id,
    }


def _schedule_from_json(data: dict[str, Any] | None) -> CampaignSchedule | None:
    if data is None:
        return None
    return CampaignSchedule(
        cron_expression=str(data["cron_expression"]),
        execution_window_hours=int(data["execution_window_hours"]),
        max_consecutive_failures=int(data.get("max_consecutive_failures", 3)),
        blackout_periods=list(data.get("blackout_periods") or []),
        consecutive_failure_count=int(data.get("consecutive_failure_count", 0)),
        scheduler_job_id=data.get("scheduler_job_id"),
    )


def _rules_to_json(rules: list[TargetSelectionRule]) -> list[dict[str, Any]]:
    return [{"attribute": r.attribute, "operator": r.operator, "value": r.value} for r in rules]


def _rules_from_json(data: list[Any]) -> list[TargetSelectionRule]:
    return [
        TargetSelectionRule(
            attribute=str(item["attribute"]),
            operator=str(item["operator"]),
            value=str(item["value"]),
        )
        for item in (data or [])
    ]


def _to_domain(row: CampaignModel) -> Campaign:
    engagement_ref: EngagementRef | None = None
    if row.engagement_id is not None and row.engagement_tenant_id is not None:
        engagement_ref = EngagementRef(
            engagement_id=row.engagement_id,
            tenant_id=row.engagement_tenant_id,
        )

    approvals = [
        CampaignApproval(
            id=CampaignApprovalId(a.id),
            record=ApprovalRecord(
                approver_id=a.approver_id,
                timestamp=a.approved_at,
                signature=a.signature,
                approval_scope=a.approval_scope,
            ),
            revoked=a.revoked,
            revoked_at=a.revoked_at,
            revoked_by=a.revoked_by,
        )
        for a in row.approvals
    ]

    objectives = [
        CampaignObjective(
            id=CampaignObjectiveId(o.id),
            objective_type=ObjectiveType(o.objective_type),
            description=o.description,
            evaluation_criteria=ObjectiveEvaluationCriteria(
                condition_type=str(o.evaluation_criteria_json.get("condition_type", "")),
                parameters=dict(o.evaluation_criteria_json.get("parameters") or {}),
            ),
            state=ObjectiveState(o.state),
            sealed=o.sealed,
        )
        for o in row.objectives
    ]

    return Campaign(
        campaign_id=CampaignId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        name=row.name,
        classification=CampaignClassification(row.classification),
        kind=CampaignKind(row.kind),
        owner_id=row.owner_id,
        state=CampaignState(row.state),
        safety_policy=_safety_policy_from_json(row.safety_policy_json),
        approval_policy=_approval_policy_from_json(row.approval_policy_json),
        engagement_ref=engagement_ref,
        objectives=objectives,
        approvals=approvals,
        target_selection_rules=_rules_from_json(row.target_selection_rules_json),
        campaign_schedule=_schedule_from_json(row.schedule_json),
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


class PgCampaignRepository(ICampaignRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, campaign: Campaign) -> None:
        stmt = select(CampaignModel).where(
            CampaignModel.id == campaign.campaign_id.value,
            CampaignModel.tenant_id == campaign.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        engagement_id = campaign.engagement_ref.engagement_id if campaign.engagement_ref else None
        engagement_tenant_id = (
            campaign.engagement_ref.tenant_id if campaign.engagement_ref else None
        )

        if row is None:
            row = CampaignModel(
                id=campaign.campaign_id.value,
                tenant_id=campaign.tenant_id.value,
                name=campaign.name,
                classification=campaign.classification.value,
                kind=campaign.kind.value,
                owner_id=campaign.owner_id,
                state=campaign.state.value,
                engagement_id=engagement_id,
                engagement_tenant_id=engagement_tenant_id,
                safety_policy_json=_safety_policy_to_json(campaign.safety_policy),
                approval_policy_json=_approval_policy_to_json(campaign.approval_policy),
                schedule_json=_schedule_to_json(campaign.campaign_schedule),
                target_selection_rules_json=_rules_to_json(campaign.target_selection_rules),
                created_at=campaign.created_at,
                updated_at=campaign.updated_at,
                row_version=campaign.version,
            )
            self._session.add(row)
            await self._session.flush()
            await self._sync_children(row, campaign)
            return

        expected = campaign.version - 1
        if expected < 1:
            expected = 1

        upd = (
            update(CampaignModel)
            .where(
                CampaignModel.id == campaign.campaign_id.value,
                CampaignModel.tenant_id == campaign.tenant_id.value,
                CampaignModel.row_version == expected,
            )
            .values(
                name=campaign.name,
                classification=campaign.classification.value,
                kind=campaign.kind.value,
                owner_id=campaign.owner_id,
                state=campaign.state.value,
                engagement_id=engagement_id,
                engagement_tenant_id=engagement_tenant_id,
                safety_policy_json=_safety_policy_to_json(campaign.safety_policy),
                approval_policy_json=_approval_policy_to_json(campaign.approval_policy),
                schedule_json=_schedule_to_json(campaign.campaign_schedule),
                target_selection_rules_json=_rules_to_json(campaign.target_selection_rules),
                updated_at=campaign.updated_at,
                row_version=campaign.version,
            )
            .returning(CampaignModel.row_version)
        )
        upd_result = await self._session.execute(upd)
        new_version = upd_result.scalar_one_or_none()
        if new_version is None:
            actual_stmt = select(CampaignModel.row_version).where(
                CampaignModel.id == campaign.campaign_id.value,
                CampaignModel.tenant_id == campaign.tenant_id.value,
            )
            actual = (await self._session.execute(actual_stmt)).scalar_one_or_none() or 0
            raise OptimisticLockConflict(
                str(campaign.campaign_id),
                expected,
                int(actual),
            )

        await self._session.refresh(row)
        await self._sync_children(row, campaign)

    async def _sync_children(self, row: CampaignModel, campaign: Campaign) -> None:
        row.approvals.clear()
        row.objectives.clear()
        await self._session.flush()

        for a in campaign.approvals:
            row.approvals.append(
                CampaignApprovalModel(
                    id=a.id.value,
                    campaign_id=campaign.campaign_id.value,
                    approver_id=a.record.approver_id,
                    signature=a.record.signature,
                    approval_scope=a.record.approval_scope,
                    approved_at=a.record.timestamp,
                    revoked=a.revoked,
                    revoked_at=a.revoked_at,
                    revoked_by=a.revoked_by,
                )
            )
        for o in campaign.objectives:
            row.objectives.append(
                CampaignObjectiveModel(
                    id=o.id.value,
                    campaign_id=campaign.campaign_id.value,
                    objective_type=o.objective_type.value,
                    description=o.description,
                    evaluation_criteria_json={
                        "condition_type": o.evaluation_criteria.condition_type,
                        "parameters": dict(o.evaluation_criteria.parameters),
                    },
                    state=o.state.value,
                    sealed=o.sealed,
                )
            )
        await self._session.flush()

    async def find_by_id(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
    ) -> Campaign | None:
        stmt = select(CampaignModel).where(
            CampaignModel.id == campaign_id.value,
            CampaignModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[Campaign]:
        from campaign.domain.value_objects.enums import CampaignState as _State

        stmt = select(CampaignModel).where(
            CampaignModel.tenant_id == tenant_id.value,
            CampaignModel.state.in_([_State.RUNNING.value, _State.PAUSED.value]),
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def find_by_engagement(
        self,
        engagement_id: UUID,
        tenant_id: TenantId,
    ) -> list[Campaign]:
        stmt = select(CampaignModel).where(
            CampaignModel.tenant_id == tenant_id.value,
            CampaignModel.engagement_id == engagement_id,
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def find_by_state(
        self,
        state: CampaignState,
        tenant_id: TenantId,
    ) -> list[Campaign]:
        stmt = select(CampaignModel).where(
            CampaignModel.tenant_id == tenant_id.value,
            CampaignModel.state == state.value,
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

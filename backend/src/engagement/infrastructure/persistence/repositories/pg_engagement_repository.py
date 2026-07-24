"""PgEngagementRepository — SQLAlchemy implementation with optimistic locking."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid7

from sqlalchemy import select, update

from engagement.domain.aggregates.engagement import Engagement
from engagement.domain.entities.engagement_entities import (
    EngagementApproval,
    EngagementParticipant,
    EngagementPhase,
    RulesOfEngagement,
    TargetScope,
)
from engagement.domain.exceptions.domain_exceptions import OptimisticLockConflict
from engagement.domain.repositories.i_engagement_repository import IEngagementRepository
from engagement.domain.value_objects.engagement_vos import (
    ApprovalPolicy,
    ApprovalRecord,
    EngagementObjectives,
    EngagementWindow,
    RoeConstraint,
    ScopeHash,
    TargetRef,
)
from engagement.domain.value_objects.enums import (
    EngagementClassification,
    EngagementState,
    KillSwitchState,
    QuorumType,
)
from engagement.domain.value_objects.identifiers import (
    EngagementApprovalId,
    EngagementId,
    EngagementParticipantId,
    EngagementPhaseId,
    TenantId,
)
from engagement.infrastructure.persistence.models.engagement_models import (
    EngagementApprovalModel,
    EngagementModel,
    EngagementParticipantModel,
    EngagementPhaseModel,
    RulesOfEngagementModel,
    TargetScopeEntryModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _policy_to_json(policy: ApprovalPolicy) -> dict[str, Any]:
    return {
        "required_approver_count": policy.required_approver_count,
        "required_approver_roles": list(policy.required_approver_roles),
        "quorum_type": policy.quorum_type.value,
    }


def _policy_from_json(data: dict[str, Any]) -> ApprovalPolicy:
    return ApprovalPolicy(
        required_approver_count=int(data["required_approver_count"]),
        required_approver_roles=list(data.get("required_approver_roles") or []),
        quorum_type=QuorumType(str(data.get("quorum_type", QuorumType.MAJORITY.value))),
    )


def _window_to_json(window: EngagementWindow | None) -> dict[str, Any] | None:
    if window is None:
        return None
    return {
        "authorized_start": window.authorized_start.isoformat(),
        "authorized_end": window.authorized_end.isoformat(),
        "operational_hours": dict(window.operational_hours),
    }


def _window_from_json(data: dict[str, Any] | None) -> EngagementWindow | None:
    if data is None:
        return None
    return EngagementWindow(
        authorized_start=datetime.fromisoformat(str(data["authorized_start"])),
        authorized_end=datetime.fromisoformat(str(data["authorized_end"])),
        operational_hours=dict(data.get("operational_hours") or {}),
    )


def _objectives_to_json(
    objectives: EngagementObjectives | None,
) -> dict[str, Any] | None:
    if objectives is None:
        return None
    return {
        "summary": objectives.summary,
        "success_criteria": list(objectives.success_criteria),
        "extras": dict(objectives.extras),
    }


def _objectives_from_json(data: dict[str, Any] | None) -> EngagementObjectives | None:
    if data is None:
        return None
    return EngagementObjectives(
        summary=str(data["summary"]),
        success_criteria=list(data.get("success_criteria") or []),
        extras=dict(data.get("extras") or {}),
    )


def _pending_to_json(targets: list[TargetRef]) -> list[dict[str, Any]]:
    return [
        {"asset_id": str(t.asset_id), "display_name": t.display_name} for t in targets
    ]


def _pending_from_json(data: list[Any] | None) -> list[TargetRef]:
    if not data:
        return []
    return [
        TargetRef(
            asset_id=UUID(str(item["asset_id"])),
            display_name=item.get("display_name"),
        )
        for item in data
    ]


def _to_domain(row: EngagementModel) -> Engagement:
    scope_targets = [
        TargetRef(asset_id=e.asset_id, display_name=e.display_name)
        for e in row.target_scope_entries
    ]
    roe_rows = sorted(row.rules_of_engagement, key=lambda r: r.version)
    roe: RulesOfEngagement | None = None
    if roe_rows:
        latest = roe_rows[-1]
        constraints = RoeConstraint(
            allowed_techniques=list(latest.constraints_json.get("allowed_techniques") or []),
            forbidden_targets=list(latest.constraints_json.get("forbidden_targets") or []),
            rate_limits=dict(latest.constraints_json.get("rate_limits") or {}),
            escalation_contacts=list(
                latest.constraints_json.get("escalation_contacts") or []
            ),
        )
        roe = RulesOfEngagement(
            version=latest.version,
            constraints=constraints,
            signed_by=latest.signed_by,
            signature=latest.signature,
            signed_at=latest.signed_at,
        )

    return Engagement(
        engagement_id=EngagementId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        name=row.name,
        classification=EngagementClassification(row.classification),
        owner_id=row.owner_id,
        state=EngagementState(row.state),
        approval_policy=_policy_from_json(row.approval_policy_json),
        window=_window_from_json(row.window_json),
        objectives=_objectives_from_json(row.objectives_json),
        scope=TargetScope(targets=scope_targets),
        roe=roe,
        approvals=[
            EngagementApproval(
                approval_id=EngagementApprovalId(a.id),
                record=ApprovalRecord(
                    approver_id=a.approver_id,
                    timestamp=a.timestamp,
                    signature=a.signature,
                    approval_scope=a.approval_scope,
                ),
                revoked=a.revoked,
                revoked_at=a.revoked_at,
                revoked_by=a.revoked_by,
            )
            for a in row.approvals
        ],
        participants=[
            EngagementParticipant(
                participant_id=EngagementParticipantId(p.id),
                operator_id=p.operator_id,
                role=p.role,
                added_at=p.added_at,
                removed_at=p.removed_at,
            )
            for p in row.participants
        ],
        phases=[
            EngagementPhase(
                phase_id=EngagementPhaseId(ph.id),
                name=ph.name,
                description=ph.description,
                sort_order=ph.sort_order,
            )
            for ph in row.phases
        ],
        kill_switch_state=KillSwitchState(row.kill_switch_state),
        scope_hash=ScopeHash(row.scope_hash) if row.scope_hash else None,
        engagement_version=row.engagement_version,
        pending_scope_expansion=_pending_from_json(row.pending_scope_expansion_json),
        created_at=row.created_at,
        updated_at=row.updated_at,
        version=row.row_version,
    )


class PgEngagementRepository(IEngagementRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, engagement: Engagement) -> None:
        stmt = select(EngagementModel).where(
            EngagementModel.id == engagement.engagement_id.value,
            EngagementModel.tenant_id == engagement.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            row = EngagementModel(
                id=engagement.engagement_id.value,
                tenant_id=engagement.tenant_id.value,
                name=engagement.name,
                classification=engagement.classification.value,
                owner_id=engagement.owner_id,
                state=engagement.state.value,
                kill_switch_state=engagement.kill_switch_state.value,
                engagement_version=engagement.engagement_version,
                scope_hash=(
                    engagement.scope_hash.value if engagement.scope_hash else None
                ),
                approval_policy_json=_policy_to_json(engagement.approval_policy),
                window_json=_window_to_json(engagement.window),
                objectives_json=_objectives_to_json(engagement.objectives),
                pending_scope_expansion_json=_pending_to_json(
                    engagement.pending_scope_expansion
                ),
                created_at=engagement.created_at,
                updated_at=engagement.updated_at,
                row_version=engagement.version,
            )
            self._session.add(row)
            await self._session.flush()
            await self._sync_children(row, engagement)
            return

        # After domain _mutate, version is N+1 relative to loaded N.
        expected = engagement.version - 1
        if expected < 1:
            expected = 1

        upd = (
            update(EngagementModel)
            .where(
                EngagementModel.id == engagement.engagement_id.value,
                EngagementModel.tenant_id == engagement.tenant_id.value,
                EngagementModel.row_version == expected,
            )
            .values(
                name=engagement.name,
                classification=engagement.classification.value,
                owner_id=engagement.owner_id,
                state=engagement.state.value,
                kill_switch_state=engagement.kill_switch_state.value,
                engagement_version=engagement.engagement_version,
                scope_hash=(
                    engagement.scope_hash.value if engagement.scope_hash else None
                ),
                approval_policy_json=_policy_to_json(engagement.approval_policy),
                window_json=_window_to_json(engagement.window),
                objectives_json=_objectives_to_json(engagement.objectives),
                pending_scope_expansion_json=_pending_to_json(
                    engagement.pending_scope_expansion
                ),
                updated_at=engagement.updated_at,
                row_version=engagement.version,
            )
            .returning(EngagementModel.row_version)
        )
        upd_result = await self._session.execute(upd)
        new_version = upd_result.scalar_one_or_none()
        if new_version is None:
            actual_stmt = select(EngagementModel.row_version).where(
                EngagementModel.id == engagement.engagement_id.value,
                EngagementModel.tenant_id == engagement.tenant_id.value,
            )
            actual = (await self._session.execute(actual_stmt)).scalar_one_or_none() or 0
            raise OptimisticLockConflict(
                str(engagement.engagement_id),
                expected,
                int(actual),
            )

        # Refresh relationships for child sync
        await self._session.refresh(row)
        await self._sync_children(row, engagement)

    async def _sync_children(self, row: EngagementModel, engagement: Engagement) -> None:
        # Replace child collections (simple sync for Phase 1)
        row.phases.clear()
        row.approvals.clear()
        row.participants.clear()
        row.rules_of_engagement.clear()
        row.target_scope_entries.clear()
        await self._session.flush()

        for ph in engagement.phases:
            row.phases.append(
                EngagementPhaseModel(
                    id=ph.phase_id.value,
                    engagement_id=engagement.engagement_id.value,
                    tenant_id=engagement.tenant_id.value,
                    name=ph.name,
                    description=ph.description,
                    sort_order=ph.sort_order,
                )
            )
        for a in engagement.approvals:
            row.approvals.append(
                EngagementApprovalModel(
                    id=a.approval_id.value,
                    engagement_id=engagement.engagement_id.value,
                    tenant_id=engagement.tenant_id.value,
                    approver_id=a.record.approver_id,
                    timestamp=a.record.timestamp,
                    signature=a.record.signature,
                    approval_scope=a.record.approval_scope,
                    revoked=a.revoked,
                    revoked_at=a.revoked_at,
                    revoked_by=a.revoked_by,
                )
            )
        for p in engagement.participants:
            row.participants.append(
                EngagementParticipantModel(
                    id=p.participant_id.value,
                    engagement_id=engagement.engagement_id.value,
                    tenant_id=engagement.tenant_id.value,
                    operator_id=p.operator_id,
                    role=p.role,
                    added_at=p.added_at,
                    removed_at=p.removed_at,
                )
            )
        if engagement.roe is not None:
            roe = engagement.roe
            row.rules_of_engagement.append(
                RulesOfEngagementModel(
                    id=uuid7(),
                    engagement_id=engagement.engagement_id.value,
                    tenant_id=engagement.tenant_id.value,
                    version=roe.version,
                    constraints_json={
                        "allowed_techniques": list(roe.constraints.allowed_techniques),
                        "forbidden_targets": list(roe.constraints.forbidden_targets),
                        "rate_limits": dict(roe.constraints.rate_limits),
                        "escalation_contacts": list(roe.constraints.escalation_contacts),
                    },
                    signed_by=roe.signed_by,
                    signature=roe.signature,
                    signed_at=roe.signed_at,
                )
            )
        for t in engagement.scope.targets:
            row.target_scope_entries.append(
                TargetScopeEntryModel(
                    id=uuid7(),
                    engagement_id=engagement.engagement_id.value,
                    tenant_id=engagement.tenant_id.value,
                    asset_id=t.asset_id,
                    display_name=t.display_name,
                )
            )
        await self._session.flush()

    async def find_by_id(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> Engagement | None:
        stmt = select(EngagementModel).where(
            EngagementModel.id == engagement_id.value,
            EngagementModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[Engagement]:
        return await self.find_by_state(EngagementState.ACTIVE, tenant_id)

    async def find_by_state(
        self,
        state: EngagementState,
        tenant_id: TenantId,
    ) -> list[Engagement]:
        stmt = select(EngagementModel).where(
            EngagementModel.tenant_id == tenant_id.value,
            EngagementModel.state == state.value,
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

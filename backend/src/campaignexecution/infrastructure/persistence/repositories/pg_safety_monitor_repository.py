"""PostgreSQL repository for CampaignSafetyMonitor aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update

from campaignexecution.domain.aggregates.campaign_safety_monitor import CampaignSafetyMonitor
from campaignexecution.domain.exceptions.domain_exceptions import ConcurrencyConflict
from campaignexecution.domain.repositories.i_campaign_safety_monitor_repository import (
    ICampaignSafetyMonitorRepository,
)
from campaignexecution.domain.value_objects.enums import MonitorState
from campaignexecution.domain.value_objects.execution_vos import (
    CampaignInstanceRef,
    PolicySnapshot,
)
from campaignexecution.domain.value_objects.identifiers import (
    CampaignInstanceId,
    SafetyMonitorId,
    TenantId,
)
from campaignexecution.infrastructure.persistence.models.execution_models import (
    CampaignSafetyMonitorModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _policy_from_json(data: dict[str, Any]) -> PolicySnapshot:
    return PolicySnapshot(
        max_concurrent_actions=data.get("max_concurrent_actions", 10),
        auto_abort_on_detection=data.get("auto_abort_on_detection", False),
        auto_abort_on_objective_failure=data.get("auto_abort_on_objective_failure", False),
        blast_radius_ceiling=data.get("blast_radius_ceiling", "Medium"),
    )


def _policy_to_json(p: PolicySnapshot) -> dict[str, Any]:
    return {
        "max_concurrent_actions": p.max_concurrent_actions,
        "auto_abort_on_detection": p.auto_abort_on_detection,
        "auto_abort_on_objective_failure": p.auto_abort_on_objective_failure,
        "blast_radius_ceiling": p.blast_radius_ceiling,
    }


def _monitor_from_row(row: CampaignSafetyMonitorModel) -> CampaignSafetyMonitor:
    return CampaignSafetyMonitor(
        monitor_id=SafetyMonitorId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        campaign_instance_ref=CampaignInstanceRef(
            instance_id=row.campaign_instance_id,
            campaign_id=row.campaign_id,
            tenant_id=row.tenant_id,
        ),
        policy_snapshot=_policy_from_json(row.policy_snapshot_json),
        monitor_state=MonitorState(row.monitor_state),
        auto_abort_triggered=row.auto_abort_triggered,
        active_operation_ids=list(row.active_operation_ids_json or []),
        version=row.row_version,
    )


class PgSafetyMonitorRepository(ICampaignSafetyMonitorRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, monitor: CampaignSafetyMonitor) -> None:
        stmt = select(CampaignSafetyMonitorModel).where(
            CampaignSafetyMonitorModel.id == monitor.monitor_id.value,
            CampaignSafetyMonitorModel.tenant_id == monitor.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            row = CampaignSafetyMonitorModel(
                id=monitor.monitor_id.value,
                tenant_id=monitor.tenant_id.value,
                campaign_instance_id=monitor.campaign_instance_ref.instance_id,
                campaign_id=monitor.campaign_instance_ref.campaign_id,
                monitor_state=monitor.monitor_state.value,
                auto_abort_triggered=monitor.auto_abort_triggered,
                active_operation_ids_json=list(monitor.active_operation_ids),
                policy_snapshot_json=_policy_to_json(monitor.policy_snapshot),
                row_version=monitor.version,
            )
            self._session.add(row)
            await self._session.flush()
            return

        expected = max(monitor.version - 1, 1)
        upd = (
            update(CampaignSafetyMonitorModel)
            .where(
                CampaignSafetyMonitorModel.id == monitor.monitor_id.value,
                CampaignSafetyMonitorModel.tenant_id == monitor.tenant_id.value,
                CampaignSafetyMonitorModel.row_version == expected,
            )
            .values(
                monitor_state=monitor.monitor_state.value,
                auto_abort_triggered=monitor.auto_abort_triggered,
                active_operation_ids_json=list(monitor.active_operation_ids),
                row_version=monitor.version,
            )
            .returning(CampaignSafetyMonitorModel.row_version)
        )
        result2 = await self._session.execute(upd)
        if result2.scalar_one_or_none() is None:
            raise ConcurrencyConflict(str(monitor.monitor_id))
        await self._session.flush()

    async def find_by_campaign_instance(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> CampaignSafetyMonitor | None:
        stmt = select(CampaignSafetyMonitorModel).where(
            CampaignSafetyMonitorModel.campaign_instance_id == instance_id.value,
            CampaignSafetyMonitorModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _monitor_from_row(row)

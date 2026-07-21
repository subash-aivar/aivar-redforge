"""PgCampaignInstanceRepository — SQLAlchemy implementation with optimistic locking."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select, update

from campaign.domain.aggregates.campaign_instance import CampaignInstance
from campaign.domain.exceptions.domain_exceptions import OptimisticLockConflict
from campaign.domain.repositories.i_campaign_instance_repository import (
    ICampaignInstanceRepository,
)
from campaign.domain.value_objects.campaign_vos import TargetRef
from campaign.domain.value_objects.enums import InstanceState
from campaign.domain.value_objects.identifiers import (
    CampaignId,
    CampaignInstanceId,
    TenantId,
)
from campaign.infrastructure.persistence.models.campaign_models import (
    CampaignInstanceModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _to_domain(row: CampaignInstanceModel) -> CampaignInstance:
    resolved_targets = [
        TargetRef(
            asset_id=UUID(str(t["asset_id"])),
            asset_type=str(t.get("asset_type", "unknown")),
        )
        for t in (row.resolved_targets_json or [])
    ]
    return CampaignInstance(
        instance_id=CampaignInstanceId(row.id),
        campaign_id=CampaignId(row.campaign_id),
        tenant_id=TenantId(row.tenant_id),
        run_number=row.run_number,
        state=InstanceState(row.state),
        resolved_targets=resolved_targets,
        started_at=row.started_at,
        completed_at=row.completed_at,
        failure_reason=row.failure_reason,
        version=row.row_version,
    )


class PgCampaignInstanceRepository(ICampaignInstanceRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, instance: CampaignInstance) -> None:
        stmt = select(CampaignInstanceModel).where(
            CampaignInstanceModel.id == instance.instance_id.value,
            CampaignInstanceModel.tenant_id == instance.tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()

        resolved_json = [
            {"asset_id": str(t.asset_id), "asset_type": t.asset_type}
            for t in instance.resolved_targets
        ]

        if row is None:
            row = CampaignInstanceModel(
                id=instance.instance_id.value,
                campaign_id=instance.campaign_id.value,
                tenant_id=instance.tenant_id.value,
                run_number=instance.run_number,
                state=instance.state.value,
                resolved_targets_json=resolved_json,
                started_at=instance.started_at,
                completed_at=instance.completed_at,
                failure_reason=instance.failure_reason,
                row_version=instance.version,
            )
            self._session.add(row)
            await self._session.flush()
            return

        expected = instance.version - 1
        if expected < 1:
            expected = 1

        upd = (
            update(CampaignInstanceModel)
            .where(
                CampaignInstanceModel.id == instance.instance_id.value,
                CampaignInstanceModel.tenant_id == instance.tenant_id.value,
                CampaignInstanceModel.row_version == expected,
            )
            .values(
                state=instance.state.value,
                resolved_targets_json=resolved_json,
                completed_at=instance.completed_at,
                failure_reason=instance.failure_reason,
                row_version=instance.version,
            )
            .returning(CampaignInstanceModel.row_version)
        )
        upd_result = await self._session.execute(upd)
        new_version = upd_result.scalar_one_or_none()
        if new_version is None:
            actual_stmt = select(CampaignInstanceModel.row_version).where(
                CampaignInstanceModel.id == instance.instance_id.value,
                CampaignInstanceModel.tenant_id == instance.tenant_id.value,
            )
            actual = (
                await self._session.execute(actual_stmt)
            ).scalar_one_or_none() or 0
            raise OptimisticLockConflict(
                str(instance.instance_id),
                expected,
                int(actual),
            )

    async def find_by_id(
        self,
        instance_id: CampaignInstanceId,
        tenant_id: TenantId,
    ) -> CampaignInstance | None:
        stmt = select(CampaignInstanceModel).where(
            CampaignInstanceModel.id == instance_id.value,
            CampaignInstanceModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_by_campaign(
        self,
        campaign_id: CampaignId,
        tenant_id: TenantId,
    ) -> list[CampaignInstance]:
        stmt = (
            select(CampaignInstanceModel)
            .where(
                CampaignInstanceModel.campaign_id == campaign_id.value,
                CampaignInstanceModel.tenant_id == tenant_id.value,
            )
            .order_by(CampaignInstanceModel.run_number)
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def find_running_by_tenant(
        self, tenant_id: TenantId
    ) -> list[CampaignInstance]:
        stmt = select(CampaignInstanceModel).where(
            CampaignInstanceModel.tenant_id == tenant_id.value,
            CampaignInstanceModel.state == InstanceState.RUNNING.value,
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

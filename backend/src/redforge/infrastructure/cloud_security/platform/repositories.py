"""PostgreSQL repositories for platform orchestration runs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import func, select

from redforge.domain.cloud_security.platform.entities import OrchestrationRun
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.platform.mappings import (
    run_from_model,
    run_to_model,
    validation_report_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudOrchestrationRunModel,
    CloudPlatformValidationReportModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgOrchestrationRunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, run: OrchestrationRun) -> None:
        result = await self._session.execute(
            select(CloudOrchestrationRunModel).where(
                CloudOrchestrationRunModel.id == run.id.value,
                CloudOrchestrationRunModel.organization_id == str(run.organization_id),
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            self._session.add(run_to_model(run))
        else:
            run_to_model(run, existing)
        await self._session.flush()

    async def get_by_id(
        self, run_id: UUID, *, organization_id: OrganizationId
    ) -> OrchestrationRun | None:
        result = await self._session.execute(
            select(CloudOrchestrationRunModel).where(
                CloudOrchestrationRunModel.id == run_id,
                CloudOrchestrationRunModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return run_from_model(row) if row is not None else None

    async def list_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[OrchestrationRun]:
        stmt = select(CloudOrchestrationRunModel).where(
            CloudOrchestrationRunModel.organization_id == str(organization_id)
        )
        if status:
            stmt = stmt.where(CloudOrchestrationRunModel.status == status)
        result = await self._session.execute(
            stmt.order_by(CloudOrchestrationRunModel.started_at.desc())
            .offset(max(0, offset))
            .limit(max(1, min(limit, 1000)))
        )
        return [run_from_model(row) for row in result.scalars().all()]

    async def count_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        status: str | None = None,
    ) -> int:
        stmt = select(func.count()).select_from(CloudOrchestrationRunModel).where(
            CloudOrchestrationRunModel.organization_id == str(organization_id)
        )
        if status:
            stmt = stmt.where(CloudOrchestrationRunModel.status == status)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def get_latest(
        self, organization_id: OrganizationId, *, target_id: str | None = None
    ) -> OrchestrationRun | None:
        stmt = select(CloudOrchestrationRunModel).where(
            CloudOrchestrationRunModel.organization_id == str(organization_id)
        )
        if target_id:
            stmt = stmt.where(CloudOrchestrationRunModel.target_id == target_id)
        result = await self._session.execute(
            stmt.order_by(CloudOrchestrationRunModel.started_at.desc()).limit(1)
        )
        row = result.scalar_one_or_none()
        return run_from_model(row) if row is not None else None


class PgPlatformValidationReportRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_report(
        self, organization_id: OrganizationId, report: dict[str, object]
    ) -> None:
        result = await self._session.execute(
            select(CloudPlatformValidationReportModel).where(
                CloudPlatformValidationReportModel.organization_id == str(organization_id)
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            self._session.add(
                validation_report_to_model(
                    str(organization_id), report, report_id=uuid4()
                )
            )
        else:
            validation_report_to_model(str(organization_id), report, model=existing)
        await self._session.flush()

    async def get_latest(
        self, organization_id: OrganizationId
    ) -> dict[str, Any] | None:
        result = await self._session.execute(
            select(CloudPlatformValidationReportModel).where(
                CloudPlatformValidationReportModel.organization_id == str(organization_id)
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return {
            "organization_id": row.organization_id,
            "report": dict(row.report or {}),
            "created_at": row.created_at.isoformat(),
        }

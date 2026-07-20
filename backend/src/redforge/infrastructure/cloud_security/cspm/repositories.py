"""PostgreSQL repository implementations for CSPM aggregates."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import func, select

from redforge.domain.cloud_security.cspm.entities import CSPMDriftBaseline
from redforge.domain.cloud_security.cspm.evaluation import CSPMEvaluation
from redforge.domain.cloud_security.cspm.finding import CSPMFinding
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import (
    CSPMEvaluationId,
    CSPMFindingId,
    CSPMPolicyId,
    FindingStatus,
)
from redforge.domain.cloud_security.repositories import Page
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId
from redforge.infrastructure.cloud_security.cspm.mappings import (
    drift_baseline_from_model,
    drift_baseline_to_model,
    evaluation_from_model,
    evaluation_to_model,
    finding_from_model,
    finding_to_model,
    policy_from_model,
    policy_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CSPMDriftBaselineModel,
    CSPMEvaluationModel,
    CSPMFindingModel,
    CSPMPolicyModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _clamp_page(page: int, size: int) -> tuple[int, int]:
    if page < 1:
        page = 1
    if size < 1:
        size = 20
    if size > 200:
        size = 200
    return page, size


class PgCSPMPolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, policy: CSPMPolicy) -> None:
        existing = await self._session.get(CSPMPolicyModel, str(policy.id))
        if existing is None:
            self._session.add(policy_to_model(policy))
        else:
            policy_to_model(policy, existing)
        await self._session.flush()

    async def save_batch(self, policies: list[CSPMPolicy]) -> None:
        for policy in policies:
            await self.save(policy)

    async def get_by_id(self, policy_id: CSPMPolicyId) -> CSPMPolicy | None:
        row = await self._session.get(CSPMPolicyModel, str(policy_id))
        return policy_from_model(row) if row is not None else None

    async def list_enabled(self) -> list[CSPMPolicy]:
        result = await self._session.execute(
            select(CSPMPolicyModel)
            .where(CSPMPolicyModel.enabled.is_(True))
            .order_by(CSPMPolicyModel.id.asc())
        )
        return [policy_from_model(row) for row in result.scalars().all()]

    async def list_all(self) -> list[CSPMPolicy]:
        result = await self._session.execute(
            select(CSPMPolicyModel).order_by(CSPMPolicyModel.id.asc())
        )
        return [policy_from_model(row) for row in result.scalars().all()]

    async def list_for_asset(
        self, *, provider_type: str, asset_type: str
    ) -> list[CSPMPolicy]:
        policies = await self.list_enabled()
        return [
            p
            for p in policies
            if p.applies_to(provider_type=provider_type, asset_type=asset_type)
        ]


class PgCSPMFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, finding: CSPMFinding) -> None:
        existing = await self._session.get(CSPMFindingModel, finding.id.value)
        if existing is None:
            self._session.add(finding_to_model(finding))
        else:
            finding_to_model(finding, existing)
        await self._session.flush()

    async def get_by_id(
        self, finding_id: CSPMFindingId, organization_id: OrganizationId
    ) -> CSPMFinding | None:
        result = await self._session.execute(
            select(CSPMFindingModel).where(
                CSPMFindingModel.id == finding_id.value,
                CSPMFindingModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return finding_from_model(row) if row is not None else None

    async def get_by_fingerprint(
        self, fingerprint: str, organization_id: OrganizationId
    ) -> CSPMFinding | None:
        result = await self._session.execute(
            select(CSPMFindingModel).where(
                CSPMFindingModel.fingerprint == fingerprint,
                CSPMFindingModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return finding_from_model(row) if row is not None else None

    async def list_by_organization(
        self,
        org_id: OrganizationId,
        *,
        page: int,
        size: int,
        status: FindingStatus | None = None,
        cloud_asset_id: CloudAssetId | None = None,
        severity: str | None = None,
    ) -> Page[CSPMFinding]:
        page, size = _clamp_page(page, size)
        base = select(CSPMFindingModel).where(
            CSPMFindingModel.organization_id == str(org_id)
        )
        if status is not None:
            base = base.where(CSPMFindingModel.status == status.value)
        if cloud_asset_id is not None:
            base = base.where(CSPMFindingModel.cloud_asset_id == cloud_asset_id.value)
        if severity is not None:
            base = base.where(CSPMFindingModel.severity == severity.upper())
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CSPMFindingModel.detected_at.desc())
            .offset((page - 1) * size)
            .limit(size)
        )
        items = [finding_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)

    async def list_open_by_asset(
        self, asset_id: CloudAssetId, organization_id: OrganizationId
    ) -> list[CSPMFinding]:
        open_statuses = (
            FindingStatus.OPEN.value,
            FindingStatus.CONFIRMED.value,
            FindingStatus.REOPENED.value,
        )
        result = await self._session.execute(
            select(CSPMFindingModel)
            .where(
                CSPMFindingModel.cloud_asset_id == asset_id.value,
                CSPMFindingModel.organization_id == str(organization_id),
                CSPMFindingModel.status.in_(open_statuses),
            )
            .order_by(CSPMFindingModel.detected_at.desc())
        )
        return [finding_from_model(row) for row in result.scalars().all()]

    async def count_open_by_severity(self, org_id: OrganizationId) -> dict[str, int]:
        open_statuses = (
            FindingStatus.OPEN.value,
            FindingStatus.CONFIRMED.value,
            FindingStatus.REOPENED.value,
        )
        result = await self._session.execute(
            select(CSPMFindingModel.severity, func.count())
            .where(
                CSPMFindingModel.organization_id == str(org_id),
                CSPMFindingModel.status.in_(open_statuses),
            )
            .group_by(CSPMFindingModel.severity)
        )
        return {str(severity): int(count) for severity, count in result.all()}


class PgCSPMEvaluationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, evaluation: CSPMEvaluation) -> None:
        existing = await self._session.get(CSPMEvaluationModel, evaluation.id.value)
        if existing is None:
            self._session.add(evaluation_to_model(evaluation))
        else:
            evaluation_to_model(evaluation, existing)
        await self._session.flush()

    async def get_by_id(
        self, evaluation_id: CSPMEvaluationId, organization_id: OrganizationId
    ) -> CSPMEvaluation | None:
        result = await self._session.execute(
            select(CSPMEvaluationModel).where(
                CSPMEvaluationModel.id == evaluation_id.value,
                CSPMEvaluationModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return evaluation_from_model(row) if row is not None else None

    async def list_by_organization(
        self, org_id: OrganizationId, *, page: int, size: int
    ) -> Page[CSPMEvaluation]:
        page, size = _clamp_page(page, size)
        base = select(CSPMEvaluationModel).where(
            CSPMEvaluationModel.organization_id == str(org_id)
        )
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CSPMEvaluationModel.started_at.desc())
            .offset((page - 1) * size)
            .limit(size)
        )
        items = [evaluation_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)


class PgCSPMDriftBaselineRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, baseline: CSPMDriftBaseline) -> None:
        existing = await self._session.get(CSPMDriftBaselineModel, baseline.id)
        if existing is None:
            self._session.add(drift_baseline_to_model(baseline))
        else:
            drift_baseline_to_model(baseline, existing)
        await self._session.flush()

    async def get_by_asset(
        self,
        organization_id: OrganizationId,
        cloud_asset_id: CloudAssetId,
        drift_kind: str,
    ) -> CSPMDriftBaseline | None:
        result = await self._session.execute(
            select(CSPMDriftBaselineModel).where(
                CSPMDriftBaselineModel.organization_id == str(organization_id),
                CSPMDriftBaselineModel.cloud_asset_id == cloud_asset_id.value,
                CSPMDriftBaselineModel.drift_kind == drift_kind,
            )
        )
        row = result.scalar_one_or_none()
        return drift_baseline_from_model(row) if row is not None else None

    async def get_by_id(
        self, baseline_id: UUID, organization_id: OrganizationId
    ) -> CSPMDriftBaseline | None:
        result = await self._session.execute(
            select(CSPMDriftBaselineModel).where(
                CSPMDriftBaselineModel.id == baseline_id,
                CSPMDriftBaselineModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return drift_baseline_from_model(row) if row is not None else None

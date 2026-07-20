"""Repository ports for cloud risk."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from redforge.domain.cloud_security.risk.factor import (
    CloudRiskAssessment,
    CloudRiskExposure,
    CloudRiskFactor,
)
from redforge.domain.cloud_security.risk.score import CloudRiskScore
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId


class CloudRiskRepository(Protocol):
    async def save(self, score: CloudRiskScore) -> None: ...

    async def get_by_id(
        self, risk_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None: ...

    async def get_current_by_asset(
        self, asset_id: CloudAssetId, *, organization_id: OrganizationId
    ) -> CloudRiskScore | None: ...

    async def list_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        min_score: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CloudRiskScore]: ...

    async def list_critical_by_organization(
        self, organization_id: OrganizationId, *, threshold: float = 7.0, limit: int = 50
    ) -> list[CloudRiskScore]: ...


class CloudRiskHistoryRepository(Protocol):
    async def append_from_score(self, score: CloudRiskScore) -> None: ...

    async def list_for_asset(
        self,
        asset_id: UUID,
        *,
        organization_id: OrganizationId,
        limit: int = 50,
    ) -> list[dict[str, object]]: ...


class CloudRiskFactorRepository(Protocol):
    async def save_batch(self, factors: list[CloudRiskFactor]) -> None: ...

    async def list_by_asset(
        self, asset_id: UUID, *, organization_id: OrganizationId
    ) -> list[CloudRiskFactor]: ...


class CloudRiskExposureRepository(Protocol):
    async def save(self, exposure: CloudRiskExposure) -> None: ...


class CloudRiskAssessmentRepository(Protocol):
    async def save(self, assessment: CloudRiskAssessment) -> None: ...

    async def get_by_id(
        self, assessment_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRiskAssessment | None: ...

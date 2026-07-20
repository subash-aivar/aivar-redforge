"""Repository interfaces for CSPM aggregates."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

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


class CSPMFindingRepository(Protocol):
    async def save(self, finding: CSPMFinding) -> None: ...

    async def get_by_id(
        self, finding_id: CSPMFindingId, organization_id: OrganizationId
    ) -> CSPMFinding | None: ...

    async def get_by_fingerprint(
        self, fingerprint: str, organization_id: OrganizationId
    ) -> CSPMFinding | None: ...

    async def list_by_organization(
        self,
        org_id: OrganizationId,
        *,
        page: int,
        size: int,
        status: FindingStatus | None = None,
        cloud_asset_id: CloudAssetId | None = None,
        severity: str | None = None,
    ) -> Page[CSPMFinding]: ...

    async def list_open_by_asset(
        self, asset_id: CloudAssetId, organization_id: OrganizationId
    ) -> list[CSPMFinding]: ...

    async def count_open_by_severity(
        self, org_id: OrganizationId
    ) -> dict[str, int]: ...


class CSPMPolicyRepository(Protocol):
    async def save(self, policy: CSPMPolicy) -> None: ...

    async def save_batch(self, policies: list[CSPMPolicy]) -> None: ...

    async def get_by_id(self, policy_id: CSPMPolicyId) -> CSPMPolicy | None: ...

    async def list_enabled(self) -> list[CSPMPolicy]: ...

    async def list_all(self) -> list[CSPMPolicy]: ...

    async def list_for_asset(
        self, *, provider_type: str, asset_type: str
    ) -> list[CSPMPolicy]: ...


class CSPMEvaluationRepository(Protocol):
    async def save(self, evaluation: CSPMEvaluation) -> None: ...

    async def get_by_id(
        self, evaluation_id: CSPMEvaluationId, organization_id: OrganizationId
    ) -> CSPMEvaluation | None: ...

    async def list_by_organization(
        self, org_id: OrganizationId, *, page: int, size: int
    ) -> Page[CSPMEvaluation]: ...


class CSPMDriftBaselineRepository(Protocol):
    async def save(self, baseline: CSPMDriftBaseline) -> None: ...

    async def get_by_asset(
        self,
        organization_id: OrganizationId,
        cloud_asset_id: CloudAssetId,
        drift_kind: str,
    ) -> CSPMDriftBaseline | None: ...

    async def get_by_id(
        self, baseline_id: UUID, organization_id: OrganizationId
    ) -> CSPMDriftBaseline | None: ...

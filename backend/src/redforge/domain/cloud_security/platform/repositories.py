"""Repository protocols for M26 Phase 8 platform orchestration."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from redforge.domain.cloud_security.platform.entities import OrchestrationRun
from redforge.domain.cloud_security.value_objects import OrganizationId


class OrchestrationRunRepository(Protocol):
    async def save(self, run: OrchestrationRun) -> None: ...

    async def get_by_id(
        self, run_id: UUID, *, organization_id: OrganizationId
    ) -> OrchestrationRun | None: ...

    async def list_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[OrchestrationRun]: ...

    async def count_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        status: str | None = None,
    ) -> int: ...

    async def get_latest(
        self, organization_id: OrganizationId, *, target_id: str | None = None
    ) -> OrchestrationRun | None: ...


class PlatformValidationReportRepository(Protocol):
    async def save_report(
        self, organization_id: OrganizationId, report: dict[str, object]
    ) -> None: ...

    async def get_latest(
        self, organization_id: OrganizationId
    ) -> dict[str, object] | None: ...

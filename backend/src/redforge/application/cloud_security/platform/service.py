"""Facade CloudPlatformService for API wiring."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from redforge.application.cloud_security.platform.bulk import paginate_offset
from redforge.application.cloud_security.platform.dtos import (
    OrchestratePlatformCommand,
    OrchestrationRunDTO,
    OrchestrationRunPageDTO,
    PackageHealthDTO,
    PlatformDiagnosticsDTO,
    PlatformHealthDTO,
    PlatformSummaryDTO,
    SyncStatusDTO,
    ValidationReportDTO,
)
from redforge.application.cloud_security.platform.health_service import (
    CloudPlatformHealthService,
)
from redforge.application.cloud_security.platform.lifecycle_service import (
    CloudPlatformLifecycleService,
)
from redforge.application.cloud_security.platform.observability import new_operation_id
from redforge.application.cloud_security.platform.orchestrator import (
    CloudPlatformOrchestrator,
    _run_to_dto,
)
from redforge.application.cloud_security.platform.synchronization_service import (
    CloudPlatformSynchronizationService,
)
from redforge.application.cloud_security.platform.validation_service import (
    CloudPlatformValidationService,
)
from redforge.domain.cloud_security.platform.exceptions import OrchestrationRunNotFoundError
from redforge.domain.cloud_security.platform.value_objects import PackageName
from redforge.domain.cloud_security.value_objects import OrganizationId


class CloudPlatformService:
    """API-facing facade composing Phase 8 platform services."""

    def __init__(
        self,
        *,
        orchestrator: CloudPlatformOrchestrator,
        lifecycle: CloudPlatformLifecycleService | None = None,
        sync: CloudPlatformSynchronizationService | None = None,
        validation: CloudPlatformValidationService | None = None,
        health: CloudPlatformHealthService | None = None,
        session_factory: Any | None = None,
        run_repo_factory: Any | None = None,
        foundation: Any | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._lifecycle = lifecycle
        self._sync = sync
        self._validation = validation or CloudPlatformValidationService()
        self._health = health or CloudPlatformHealthService()
        self._session_factory = session_factory
        self._run_repo_factory = run_repo_factory
        self._foundation = foundation

    async def orchestrate(self, command: OrchestratePlatformCommand) -> OrchestrationRunDTO:
        return await self._orchestrator.orchestrate(command)

    async def health(self) -> PlatformHealthDTO:
        return self._health.check_all()

    async def health_package(self, package: str) -> PackageHealthDTO:
        return self._health.check_package(PackageName(package))

    async def readiness(self, organization_id: str) -> PlatformHealthDTO:
        return await self._health.readiness(organization_id)

    async def validate(
        self, organization_id: str, *, persist: bool = True
    ) -> ValidationReportDTO:
        return await self._validation.validate(organization_id, persist=persist)

    async def last_validation_report(
        self, organization_id: str
    ) -> ValidationReportDTO | None:
        return await self._validation.get_last_report(organization_id)

    async def sync_status(
        self, organization_id: str, *, cloud_account_id: UUID | None = None
    ) -> SyncStatusDTO:
        if self._sync is None:
            return SyncStatusDTO(
                organization_id=organization_id,
                accounts=[],
                last_orchestration=None,
                aggregated_status="UNKNOWN",
            )
        return await self._sync.get_sync_status(
            organization_id, cloud_account_id=cloud_account_id
        )

    async def list_runs(
        self,
        organization_id: str,
        *,
        page: int = 1,
        size: int = 50,
        status: str | None = None,
    ) -> OrchestrationRunPageDTO:
        limit, offset = paginate_offset(page=page, size=size)
        if self._session_factory is None or self._run_repo_factory is None:
            return OrchestrationRunPageDTO(items=[], page=page, size=size, total=0)
        org = OrganizationId(organization_id)
        async with self._session_factory() as session:
            repo = self._run_repo_factory(session)
            items = await repo.list_by_organization(
                org, status=status, limit=limit, offset=offset
            )
            total = await repo.count_by_organization(org, status=status)
        return OrchestrationRunPageDTO(
            items=[_run_to_dto(r) for r in items],
            page=max(1, page),
            size=limit,
            total=total,
        )

    async def get_run(self, organization_id: str, run_id: UUID) -> OrchestrationRunDTO:
        if self._session_factory is None or self._run_repo_factory is None:
            raise OrchestrationRunNotFoundError(str(run_id))
        async with self._session_factory() as session:
            repo = self._run_repo_factory(session)
            run = await repo.get_by_id(run_id, organization_id=OrganizationId(organization_id))
        if run is None:
            raise OrchestrationRunNotFoundError(str(run_id))
        return _run_to_dto(run)

    async def summary(self, organization_id: str) -> PlatformSummaryDTO:
        health = await self.health()
        last_report = await self.last_validation_report(organization_id)
        account_count = 0
        provider_count = 0
        if self._foundation is not None:
            from redforge.application.cloud_security.foundation_dtos import (
                ListCloudAccountsQuery,
                ListCloudProvidersQuery,
            )

            providers = await self._foundation.list_cloud_providers(
                ListCloudProvidersQuery(organization_id=organization_id)
            )
            accounts = await self._foundation.list_cloud_accounts(
                ListCloudAccountsQuery(organization_id=organization_id, page=1, size=1)
            )
            provider_count = len(providers)
            account_count = accounts.total

        last_run_status = None
        last_run_id = None
        last_run_at = None
        if self._session_factory is not None and self._run_repo_factory is not None:
            async with self._session_factory() as session:
                repo = self._run_repo_factory(session)
                latest = await repo.get_latest(OrganizationId(organization_id))
            if latest is not None:
                last_run_status = latest.status.value
                last_run_id = str(latest.id)
                last_run_at = latest.started_at

        return PlatformSummaryDTO(
            organization_id=organization_id,
            account_count=account_count,
            provider_count=provider_count,
            last_run_status=last_run_status,
            last_run_id=last_run_id,
            last_run_at=last_run_at,
            health_overall=health.overall,
            validation_passed=last_report.overall_passed if last_report else None,
        )

    async def diagnostics(self, organization_id: str) -> PlatformDiagnosticsDTO:
        health = await self.health()
        sync = await self.sync_status(organization_id)
        last_run: OrchestrationRunDTO | None = None
        if self._session_factory is not None and self._run_repo_factory is not None:
            async with self._session_factory() as session:
                repo = self._run_repo_factory(session)
                latest = await repo.get_latest(OrganizationId(organization_id))
            if latest is not None:
                last_run = _run_to_dto(latest)
        return PlatformDiagnosticsDTO(
            organization_id=organization_id,
            operation_id=new_operation_id(),
            health=health,
            last_run=last_run,
            sync=sync,
            notes=[
                "Orchestration runs are the operational audit trail.",
                "Secrets/credentials are never logged.",
                "No workers/schedules/dashboards in Phase 8 integration layer.",
            ],
        )

    @property
    def lifecycle(self) -> CloudPlatformLifecycleService | None:
        return self._lifecycle

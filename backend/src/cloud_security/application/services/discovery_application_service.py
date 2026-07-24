"""DiscoveryApplicationService — the canonical entrypoint for every
Resource Discovery operation (M45E).

Starts discovery, coordinates a registered `IDiscoveryProvider`,
imports discovered `CloudResource`s into the Asset Inventory (M45B),
and tracks `CloudDiscoveryJob` (M45E) progress/completion — nothing
else. This service never evaluates security, never calculates risk,
never determines compliance. `CloudAsset` (M45B) remains the single
source of truth for asset data; this service only maps discovered
resources into `AssetInventoryApplicationService` calls, it never
owns or stores asset data itself. `attach`-style operations act on
caller-supplied `CloudAccount`/`CloudDiscoveryJob` instances (no
persistence for either, the same discipline every prior
`cloud_security` service follows); the discovery-job side is tracked
through the injected `IDiscoveryRegistry`. This service holds no state
between calls beyond its injected collaborators, so it stays
stateless."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.commands.asset_inventory_commands import (
    RegisterAssetCommand,
    UpdateAssetCommand,
)
from cloud_security.application.commands.discovery_commands import StartDiscoveryCommand
from cloud_security.application.dtos.discovery_job_record import DiscoveryJobRecord
from cloud_security.application.dtos.discovery_outcomes import (
    BatchDiscoveryFailure,
    BatchDiscoveryResult,
    BatchDiscoveryStatus,
    DiscoveryCancelled,
    DiscoveryStarted,
    DiscoveryStatistics,
)
from cloud_security.application.exceptions import (
    CredentialNotAttachedError,
    DiscoveryJobNotFoundError,
    NoDiscoveryProviderRegisteredError,
    UnsupportedProviderError,
)
from cloud_security.application.services import discovery_validation
from cloud_security.domain.aggregates.cloud_discovery_job import CloudDiscoveryJob
from cloud_security.domain.value_objects.enums import DiscoveryJobStatus
from cloud_security.domain.value_objects.identifiers import DiscoveryJobId

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cloud_security.application.commands.discovery_commands import (
        BatchDiscoveryCommand,
        CancelDiscoveryCommand,
        DiscoverOrganizationCommand,
        RefreshDiscoveryCommand,
    )
    from cloud_security.application.ports.i_credential_reference_registry import (
        ICredentialReferenceRegistry,
    )
    from cloud_security.application.ports.i_discovery_provider import IDiscoveryProvider
    from cloud_security.application.ports.i_discovery_registry import IDiscoveryRegistry
    from cloud_security.application.ports.i_provider_registry import IProviderRegistry
    from cloud_security.application.queries.discovery_queries import (
        DiscoveryStatisticsQuery,
        GetDiscoveryStatusQuery,
        ListDiscoveredAssetsQuery,
        ListDiscoveryJobsQuery,
    )
    from cloud_security.application.services.asset_inventory_application_service import (
        AssetInventoryApplicationService,
    )
    from cloud_security.domain.aggregates.cloud_account import CloudAccount
    from cloud_security.domain.aggregates.cloud_asset import CloudAsset
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import TenantId


def _to_record(job: CloudDiscoveryJob) -> DiscoveryJobRecord:
    return DiscoveryJobRecord(
        job_id=str(job.job_id),
        tenant_id=str(job.tenant_id),
        account_id=str(job.account_id),
        provider_id=str(job.provider_id),
        status=job.status,
        started_at=job.started_at,
        discovered_count=job.discovered_count,
        updated_count=job.updated_count,
        failed_count=job.failed_count,
        discovered_asset_ids=job.discovered_asset_ids,
        completed_at=job.completed_at,
        cancelled_at=job.cancelled_at,
        failure_reason=job.failure_reason,
    )


class DiscoveryApplicationService:
    def __init__(
        self,
        job_registry: IDiscoveryRegistry,
        provider_registry: IProviderRegistry,
        credential_registry: ICredentialReferenceRegistry,
        asset_inventory_service: AssetInventoryApplicationService,
        discovery_providers: Mapping[CloudPlatformType, IDiscoveryProvider],
    ) -> None:
        self._job_registry = job_registry
        self._provider_registry = provider_registry
        self._credential_registry = credential_registry
        self._asset_inventory_service = asset_inventory_service
        self._discovery_providers = discovery_providers

    # -- commands ------------------------------------------------------

    def start_discovery(
        self,
        cmd: StartDiscoveryCommand,
        account: CloudAccount,
        existing_assets: Mapping[str, CloudAsset] | None = None,
    ) -> DiscoveryStarted:
        discovery_validation.validate_account_matches(account, cmd.account_id)

        provider_record = self._provider_registry.get(cmd.tenant_id, cmd.provider_id)
        if provider_record is None:
            raise UnsupportedProviderError(cmd.provider_id)
        discovery_validation.validate_provider_enabled(provider_record)
        discovery_validation.validate_provider_has_discovery_capability(provider_record)

        credential = self._credential_registry.get_active_for_account_provider(
            cmd.tenant_id, cmd.account_id, cmd.provider_id
        )
        if credential is None:
            raise CredentialNotAttachedError(cmd.account_id, cmd.provider_id)

        discovery_provider = self._discovery_providers.get(provider_record.platform_type)
        if discovery_provider is None:
            raise NoDiscoveryProviderRegisteredError(provider_record.platform_type)

        now = datetime.now(UTC)
        account.start_discovery(cmd.tenant_id)

        job = CloudDiscoveryJob.start(
            job_id=DiscoveryJobId.generate(),
            tenant_id=cmd.tenant_id,
            account_id=cmd.account_id,
            provider_id=cmd.provider_id,
            window=cmd.window,
            now=now,
        )
        self._job_registry.register(job)

        try:
            resources = discovery_provider.discover(cmd.account_id, cmd.window)
        except Exception as exc:
            job.fail(cmd.tenant_id, str(exc), datetime.now(UTC))
            self._job_registry.release(job)
            account.fail_discovery(cmd.tenant_id)
            return DiscoveryStarted(record=_to_record(job))

        existing = existing_assets or {}
        for resource in resources:
            try:
                known_asset = existing.get(str(resource.resource_id))
                if known_asset is not None:
                    self._asset_inventory_service.update_asset(
                        known_asset, UpdateAssetCommand(tenant_id=cmd.tenant_id)
                    )
                    job.record_discovered_asset(
                        cmd.tenant_id, str(known_asset.asset_id), updated=True
                    )
                else:
                    registered = self._asset_inventory_service.register_asset(
                        RegisterAssetCommand(
                            tenant_id=cmd.tenant_id, account_id=cmd.account_id, resource=resource
                        )
                    )
                    job.record_discovered_asset(
                        cmd.tenant_id, registered.record.asset_id, updated=False
                    )
            except Exception:
                job.record_failure(cmd.tenant_id)

        job.complete(cmd.tenant_id, datetime.now(UTC))
        self._job_registry.release(job)
        account.complete_discovery(
            cmd.tenant_id, job.discovered_count + job.updated_count, datetime.now(UTC)
        )
        return DiscoveryStarted(record=_to_record(job))

    def discover_organization(
        self, cmd: DiscoverOrganizationCommand, accounts: Mapping[str, CloudAccount]
    ) -> BatchDiscoveryResult:
        sub_commands = tuple(
            StartDiscoveryCommand(
                tenant_id=cmd.tenant_id,
                account_id=account_id,
                provider_id=cmd.provider_id,
                window=cmd.window,
            )
            for account_id in cmd.account_ids
        )
        return self._run_batch(sub_commands, accounts)

    def register_batch(
        self, cmd: BatchDiscoveryCommand, accounts: Mapping[str, CloudAccount]
    ) -> BatchDiscoveryResult:
        discovery_validation.validate_batch_not_empty(cmd.commands)
        return self._run_batch(cmd.commands, accounts)

    def _run_batch(
        self, commands: tuple[StartDiscoveryCommand, ...], accounts: Mapping[str, CloudAccount]
    ) -> BatchDiscoveryResult:
        started: list[DiscoveryStarted] = []
        failures: list[BatchDiscoveryFailure] = []
        for index, sub_cmd in enumerate(commands):
            try:
                account = accounts[str(sub_cmd.account_id)]
                started.append(self.start_discovery(sub_cmd, account))
            except Exception as exc:
                failures.append(
                    BatchDiscoveryFailure(
                        index=index, error_type=type(exc).__name__, message=str(exc)
                    )
                )

        if not failures:
            status = BatchDiscoveryStatus.SUCCEEDED
        elif not started:
            status = BatchDiscoveryStatus.FAILED
        else:
            status = BatchDiscoveryStatus.PARTIALLY_SUCCEEDED

        return BatchDiscoveryResult(status=status, started=tuple(started), failures=tuple(failures))

    def refresh_discovery(
        self,
        cmd: RefreshDiscoveryCommand,
        account: CloudAccount,
        existing_assets: Mapping[str, CloudAsset] | None = None,
    ) -> DiscoveryStarted:
        old_job = self._require_job(cmd.tenant_id, cmd.job_id)
        new_cmd = StartDiscoveryCommand(
            tenant_id=cmd.tenant_id,
            account_id=old_job.account_id,
            provider_id=old_job.provider_id,
            window=cmd.window,
        )
        return self.start_discovery(new_cmd, account, existing_assets)

    def cancel_discovery(self, cmd: CancelDiscoveryCommand) -> DiscoveryCancelled:
        job = self._require_job(cmd.tenant_id, cmd.job_id)
        job.cancel(cmd.tenant_id, datetime.now(UTC))
        self._job_registry.release(job)
        return DiscoveryCancelled(job_id=str(job.job_id), tenant_id=str(job.tenant_id))

    def _require_job(self, tenant_id: TenantId, job_id: DiscoveryJobId) -> CloudDiscoveryJob:
        job = self._job_registry.get(tenant_id, job_id)
        if job is None:
            raise DiscoveryJobNotFoundError(job_id)
        return job

    # -- queries ---------------------------------------------------------

    def get_discovery_status(self, query: GetDiscoveryStatusQuery) -> DiscoveryJobRecord | None:
        job = self._job_registry.get(query.tenant_id, query.job_id)
        return _to_record(job) if job is not None else None

    def list_discovery_jobs(self, query: ListDiscoveryJobsQuery) -> tuple[DiscoveryJobRecord, ...]:
        return tuple(
            _to_record(j) for j in self._job_registry.list(query.tenant_id, query.account_id)
        )

    def list_discovered_assets(self, query: ListDiscoveredAssetsQuery) -> tuple[str, ...]:
        job = self._require_job(query.tenant_id, query.job_id)
        return job.discovered_asset_ids

    def discovery_statistics(self, query: DiscoveryStatisticsQuery) -> DiscoveryStatistics:
        jobs = self._job_registry.list(query.tenant_id, query.account_id)
        total_assets = sum(len(j.discovered_asset_ids) for j in jobs)
        return DiscoveryStatistics(
            total_jobs=len(jobs),
            in_progress_jobs=sum(1 for j in jobs if j.status == DiscoveryJobStatus.IN_PROGRESS),
            completed_jobs=sum(1 for j in jobs if j.status == DiscoveryJobStatus.COMPLETED),
            failed_jobs=sum(1 for j in jobs if j.status == DiscoveryJobStatus.FAILED),
            cancelled_jobs=sum(1 for j in jobs if j.status == DiscoveryJobStatus.CANCELLED),
            total_assets_discovered=total_assets,
        )

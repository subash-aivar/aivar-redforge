"""Sync status aggregation from foundation accounts + last orchestration run."""

from __future__ import annotations

from typing import Any, Protocol
from uuid import UUID

from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountPageDTO,
    ListCloudAccountsQuery,
)
from redforge.application.cloud_security.platform.dtos import SyncStatusDTO
from redforge.domain.cloud_security.platform.entities import OrchestrationRun
from redforge.domain.cloud_security.value_objects import OrganizationId


class _FoundationSyncPort(Protocol):
    async def list_cloud_accounts(self, query: ListCloudAccountsQuery) -> CloudAccountPageDTO: ...


class _RunRepoPort(Protocol):
    async def get_latest(
        self, organization_id: OrganizationId, *, target_id: str | None = None
    ) -> OrchestrationRun | None: ...


class CloudPlatformSynchronizationService:
    def __init__(
        self,
        foundation: _FoundationSyncPort,
        *,
        run_repo_factory: type[Any] | Any | None = None,
        session_factory: Any | None = None,
        latest_run_loader: Any | None = None,
    ) -> None:
        self._foundation = foundation
        self._run_repo_factory = run_repo_factory
        self._session_factory = session_factory
        self._latest_run_loader = latest_run_loader

    async def get_sync_status(
        self,
        organization_id: str,
        *,
        cloud_account_id: UUID | None = None,
    ) -> SyncStatusDTO:
        page = await self._foundation.list_cloud_accounts(
            ListCloudAccountsQuery(organization_id=organization_id, page=1, size=200)
        )
        accounts: list[dict[str, Any]] = []
        for acct in page.items:
            if cloud_account_id is not None and acct.account_id != str(cloud_account_id):
                continue
            accounts.append(
                {
                    "account_id": acct.account_id,
                    "display_name": acct.display_name,
                    "sync_status": acct.sync_status,
                    "external_id": acct.external_id,
                    # credential_reference_id intentionally omitted from sync surface
                }
            )

        target = str(cloud_account_id) if cloud_account_id else None
        last = await self._load_latest(organization_id, target_id=target)
        last_payload: dict[str, Any] | None = None
        if last is not None:
            last_payload = {
                "run_id": str(last.id),
                "status": last.status.value,
                "target_id": last.target_id,
                "started_at": last.started_at.isoformat(),
                "completed_at": last.completed_at.isoformat() if last.completed_at else None,
            }

        statuses = {a["sync_status"] for a in accounts}
        if not accounts:
            aggregated = "EMPTY"
        elif statuses == {"SYNCED"}:
            aggregated = "SYNCED"
        elif "FAILED" in statuses:
            aggregated = "DEGRADED"
        elif "SYNCING" in statuses:
            aggregated = "SYNCING"
        else:
            aggregated = "PENDING"

        if last is not None and last.status.value in {"FAILED", "PARTIAL"}:
            aggregated = "DEGRADED"

        return SyncStatusDTO(
            organization_id=organization_id,
            accounts=accounts,
            last_orchestration=last_payload,
            aggregated_status=aggregated,
        )

    async def _load_latest(
        self, organization_id: str, *, target_id: str | None
    ) -> OrchestrationRun | None:
        if self._latest_run_loader is not None:
            loaded: OrchestrationRun | None = await self._latest_run_loader(
                organization_id, target_id=target_id
            )
            return loaded
        if self._session_factory is None or self._run_repo_factory is None:
            return None
        async with self._session_factory() as session:
            repo: _RunRepoPort = self._run_repo_factory(session)
            return await repo.get_latest(
                OrganizationId(organization_id), target_id=target_id
            )

"""Lifecycle and synchronization service unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountDTO,
    CloudAccountPageDTO,
    CloudProviderDTO,
    RegisterCloudAccountCommand,
    RegisterCloudProviderCommand,
)
from redforge.application.cloud_security.platform.dtos import (
    RegisterAccountLifecycleCommand,
    RegisterProviderLifecycleCommand,
)
from redforge.application.cloud_security.platform.lifecycle_service import (
    CloudPlatformLifecycleService,
)
from redforge.application.cloud_security.platform.synchronization_service import (
    CloudPlatformSynchronizationService,
)
from redforge.domain.cloud_security.platform.entities import OrchestrationRun
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationScope,
    RunStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId

ORG = "01HXORG0000000000000000001"
NOW = datetime.now(UTC)


class _FakeFoundation:
    def __init__(self) -> None:
        self.providers: list[RegisterCloudProviderCommand] = []
        self.accounts: list[RegisterCloudAccountCommand] = []
        self.account_rows: list[CloudAccountDTO] = []

    async def register_cloud_provider(
        self, command: RegisterCloudProviderCommand
    ) -> CloudProviderDTO:
        self.providers.append(command)
        return CloudProviderDTO(
            provider_id=str(uuid4()),
            organization_id=command.organization_id,
            provider_type=command.provider_type,
            display_name=command.display_name,
            status="ACTIVE",
            polling_interval_seconds=command.polling_interval_seconds,
            region_filter=list(command.region_filter),
            service_filter=list(command.service_filter),
            created_at=NOW,
            updated_at=NOW,
            version=1,
        )

    async def register_cloud_account(
        self, command: RegisterCloudAccountCommand
    ) -> CloudAccountDTO:
        self.accounts.append(command)
        dto = CloudAccountDTO(
            account_id=str(uuid4()),
            cloud_provider_id=command.cloud_provider_id,
            organization_id=command.organization_id,
            external_id=command.external_id,
            display_name=command.display_name,
            account_type=command.account_type,
            credential_reference_id=command.credential_reference_id,
            sync_status="PENDING",
            tags=command.tags or {},
            created_at=NOW,
            updated_at=NOW,
            version=1,
        )
        self.account_rows.append(dto)
        return dto

    async def list_cloud_accounts(self, query: Any) -> CloudAccountPageDTO:
        return CloudAccountPageDTO(
            items=list(self.account_rows),
            page=1,
            size=50,
            total=len(self.account_rows),
        )


@pytest.mark.parametrize("provider_type", ["AWS", "AZURE", "GCP"])
@pytest.mark.asyncio
async def test_lifecycle_register_provider(provider_type: str) -> None:
    foundation = _FakeFoundation()
    svc = CloudPlatformLifecycleService(foundation)
    dto = await svc.register_provider(
        RegisterProviderLifecycleCommand(
            organization_id=ORG,
            provider_type=provider_type,
            display_name=f"{provider_type} prod",
        )
    )
    assert dto.provider_type == provider_type
    assert len(foundation.providers) == 1


@pytest.mark.parametrize("account_type", ["ROOT", "MEMBER", "STANDALONE"])
@pytest.mark.asyncio
async def test_lifecycle_register_account(account_type: str) -> None:
    foundation = _FakeFoundation()
    svc = CloudPlatformLifecycleService(foundation)
    dto = await svc.register_account(
        RegisterAccountLifecycleCommand(
            organization_id=ORG,
            cloud_provider_id=str(uuid4()),
            external_id="111122223333",
            display_name="main",
            account_type=account_type,
            credential_reference_id="cred-1",
        )
    )
    assert dto.account_type == account_type
    # credential id accepted by foundation but not leaked in sync aggregation tests
    assert foundation.accounts[0].credential_reference_id == "cred-1"


@pytest.mark.parametrize(
    ("sync_statuses", "expected"),
    [
        (["SYNCED"], "SYNCED"),
        (["PENDING"], "PENDING"),
        (["SYNCING", "SYNCED"], "SYNCING"),
        (["FAILED", "SYNCED"], "DEGRADED"),
        ([], "EMPTY"),
    ],
)
@pytest.mark.asyncio
async def test_sync_aggregation(sync_statuses: list[str], expected: str) -> None:
    foundation = _FakeFoundation()
    for i, st in enumerate(sync_statuses):
        foundation.account_rows.append(
            CloudAccountDTO(
                account_id=str(uuid4()),
                cloud_provider_id=str(uuid4()),
                organization_id=ORG,
                external_id=f"e{i}",
                display_name=f"a{i}",
                account_type="STANDALONE",
                credential_reference_id="cred",
                sync_status=st,
                tags={},
                created_at=NOW,
                updated_at=NOW,
                version=1,
            )
        )

    async def _latest(org: str, *, target_id: str | None = None) -> None:
        return None

    svc = CloudPlatformSynchronizationService(foundation, latest_run_loader=_latest)
    status = await svc.get_sync_status(ORG)
    assert status.aggregated_status == expected
    for acct in status.accounts:
        assert "credential_reference_id" not in acct


@pytest.mark.asyncio
async def test_sync_degraded_when_last_run_partial() -> None:
    foundation = _FakeFoundation()
    foundation.account_rows.append(
        CloudAccountDTO(
            account_id=str(uuid4()),
            cloud_provider_id=str(uuid4()),
            organization_id=ORG,
            external_id="e",
            display_name="a",
            account_type="STANDALONE",
            credential_reference_id="cred",
            sync_status="SYNCED",
            tags={},
            created_at=NOW,
            updated_at=NOW,
            version=1,
        )
    )

    async def _latest(org: str, *, target_id: str | None = None) -> OrchestrationRun:
        run = OrchestrationRun.start(
            organization_id=OrganizationId(ORG),
            scope=OrchestrationScope.ACCOUNT,
            target_id="t",
            operation_id="op_x",
            now=NOW,
        )
        run.status = RunStatus.PARTIAL
        return run

    svc = CloudPlatformSynchronizationService(foundation, latest_run_loader=_latest)
    status = await svc.get_sync_status(ORG)
    assert status.aggregated_status == "DEGRADED"
    assert status.last_orchestration is not None


@pytest.mark.parametrize("account_id", [uuid4() for _ in range(5)])
@pytest.mark.asyncio
async def test_sync_filter_account(account_id: UUID) -> None:
    foundation = _FakeFoundation()
    other = uuid4()
    for aid, name in ((account_id, "keep"), (other, "drop")):
        foundation.account_rows.append(
            CloudAccountDTO(
                account_id=str(aid),
                cloud_provider_id=str(uuid4()),
                organization_id=ORG,
                external_id=name,
                display_name=name,
                account_type="STANDALONE",
                credential_reference_id="cred",
                sync_status="SYNCED",
                tags={},
                created_at=NOW,
                updated_at=NOW,
                version=1,
            )
        )

    async def _latest(org: str, *, target_id: str | None = None) -> None:
        return None

    svc = CloudPlatformSynchronizationService(foundation, latest_run_loader=_latest)
    status = await svc.get_sync_status(ORG, cloud_account_id=account_id)
    assert len(status.accounts) == 1
    assert status.accounts[0]["account_id"] == str(account_id)

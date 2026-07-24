from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from cloud_security.application.commands.discovery_commands import (
    BatchDiscoveryCommand,
    CancelDiscoveryCommand,
    DiscoverOrganizationCommand,
    RefreshDiscoveryCommand,
    StartDiscoveryCommand,
)
from cloud_security.application.dtos.discovery_outcomes import BatchDiscoveryStatus
from cloud_security.application.exceptions import (
    AccountMismatchError,
    CredentialNotAttachedError,
    DiscoveryJobNotFoundError,
    DuplicateDiscoveryJobError,
    EmptyBatchDiscoveryError,
    MissingDiscoveryCapabilityError,
    NoDiscoveryProviderRegisteredError,
    ProviderNotEnabledError,
    UnsupportedProviderError,
)
from cloud_security.application.queries.discovery_queries import (
    DiscoveryStatisticsQuery,
    GetDiscoveryStatusQuery,
    ListDiscoveredAssetsQuery,
    ListDiscoveryJobsQuery,
)
from cloud_security.application.registry.in_memory_asset_inventory_registry import (
    InMemoryAssetInventoryRegistry,
)
from cloud_security.application.registry.in_memory_credential_reference_registry import (
    InMemoryCredentialReferenceRegistry,
)
from cloud_security.application.registry.in_memory_discovery_job_registry import (
    InMemoryDiscoveryJobRegistry,
)
from cloud_security.application.registry.in_memory_provider_registry import (
    InMemoryProviderRegistry,
)
from cloud_security.application.services.asset_inventory_application_service import (
    AssetInventoryApplicationService,
)
from cloud_security.application.services.discovery_application_service import (
    DiscoveryApplicationService,
)
from cloud_security.domain.aggregates.cloud_account import CloudAccount
from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.aggregates.cloud_discovery_job import CloudDiscoveryJob
from cloud_security.domain.aggregates.cloud_provider_registration import (
    CloudProviderRegistration,
)
from cloud_security.domain.aggregates.credential_association import CredentialAssociation
from cloud_security.domain.value_objects.cloud_credential_reference import (
    CloudCredentialReference,
)
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_resource import CloudResource
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
from cloud_security.domain.value_objects.enums import (
    CloudAssetType,
    CloudDiscoveryState,
    CloudPlatformType,
    CloudRiskLevel,
    ProviderCapability,
)
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    AssetId,
    CredentialAssociationId,
    DiscoveryJobId,
    ProviderId,
    ResourceId,
    TenantId,
)
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet

NOW = datetime.now(UTC)
WINDOW = DiscoveryWindow(start=NOW - timedelta(hours=1), end=NOW)


class FakeDiscoveryProvider:
    def __init__(self, platform_type, resources=(), error=None):
        self._platform_type = platform_type
        self._resources = resources
        self._error = error

    @property
    def platform_type(self):
        return self._platform_type

    def discover(self, account_id, window):
        if self._error is not None:
            raise self._error
        return self._resources


def _resource(native_id: str = "i-1") -> CloudResource:
    return CloudResource(
        resource_id=ResourceId(native_id),
        native_id=native_id,
        asset_type=CloudAssetType.COMPUTE_INSTANCE,
    )


class Harness:
    def __init__(self, resources=(), provider_enabled=True, with_discovery_capability=True):
        self.tenant_id = TenantId.generate()
        self.account = CloudAccount.register(
            account_id=AccountId.generate(),
            tenant_id=self.tenant_id,
            provider_id=ProviderId.generate(),
            platform_type=CloudPlatformType.AWS,
            display_name="prod-account",
            tags=CloudTagSet(),
            now=NOW,
        )

        capabilities = ProviderCapabilitySet(
            capabilities=(ProviderCapability.DISCOVERY,) if with_discovery_capability else ()
        )
        self.provider = CloudProviderRegistration.register(
            provider_id=ProviderId.generate(),
            tenant_id=self.tenant_id,
            platform_type=CloudPlatformType.AWS,
            display_name="aws-primary",
            capabilities=capabilities,
            now=NOW,
        )
        if provider_enabled:
            self.provider.enable(self.tenant_id, NOW)

        self.provider_registry = InMemoryProviderRegistry()
        self.provider_registry.register(self.provider)

        self.credential_registry = InMemoryCredentialReferenceRegistry()
        self.credential_association = CredentialAssociation.attach(
            association_id=CredentialAssociationId.generate(),
            tenant_id=self.tenant_id,
            account_id=self.account.account_id,
            provider_id=self.provider.provider_id,
            reference=CloudCredentialReference(credential_id="cred-1", credential_type="role_arn"),
            now=NOW,
        )
        self.credential_registry.register(self.credential_association)

        self.job_registry = InMemoryDiscoveryJobRegistry()
        self.asset_inventory_service = AssetInventoryApplicationService(
            InMemoryAssetInventoryRegistry()
        )
        self.discovery_providers = {CloudPlatformType.AWS: FakeDiscoveryProvider(
            CloudPlatformType.AWS, resources=resources
        )}

        self.service = DiscoveryApplicationService(
            job_registry=self.job_registry,
            provider_registry=self.provider_registry,
            credential_registry=self.credential_registry,
            asset_inventory_service=self.asset_inventory_service,
            discovery_providers=self.discovery_providers,
        )

    def start_cmd(self, **overrides) -> StartDiscoveryCommand:
        defaults = {
            "tenant_id": self.tenant_id,
            "account_id": self.account.account_id,
            "provider_id": self.provider.provider_id,
            "window": WINDOW,
        }
        defaults.update(overrides)
        return StartDiscoveryCommand(**defaults)


# ---------------------------------------------------------------------------
# happy path / lifecycle
# ---------------------------------------------------------------------------


def test_start_discovery_completes_and_imports_assets() -> None:
    h = Harness(resources=(_resource("i-1"), _resource("i-2")))

    outcome = h.service.start_discovery(h.start_cmd(), h.account)

    assert outcome.record.status.value == "completed"
    assert outcome.record.discovered_count == 2
    assert outcome.record.updated_count == 0
    assert len(outcome.record.discovered_asset_ids) == 2
    assert h.account.discovery_state == CloudDiscoveryState.COMPLETED


def test_start_discovery_with_no_resources() -> None:
    h = Harness(resources=())
    outcome = h.service.start_discovery(h.start_cmd(), h.account)
    assert outcome.record.status.value == "completed"
    assert outcome.record.discovered_count == 0


def test_start_discovery_updates_known_asset() -> None:
    h = Harness(resources=(_resource("i-1"),))
    existing_asset = CloudAsset.discover(
        asset_id=AssetId.generate(),
        tenant_id=h.tenant_id,
        account_id=h.account.account_id,
        resource=_resource("i-1"),
        tags=CloudTagSet(),
        risk_level=CloudRiskLevel.LOW,
        metadata=CloudMetadata(),
        now=NOW,
    )

    outcome = h.service.start_discovery(
        h.start_cmd(), h.account, existing_assets={"i-1": existing_asset}
    )

    assert outcome.record.updated_count == 1
    assert outcome.record.discovered_count == 0


def test_provider_exception_fails_job_and_account() -> None:
    h = Harness()
    h.discovery_providers[CloudPlatformType.AWS] = FakeDiscoveryProvider(
        CloudPlatformType.AWS, error=RuntimeError("boom")
    )

    outcome = h.service.start_discovery(h.start_cmd(), h.account)

    assert outcome.record.status.value == "failed"
    assert outcome.record.failure_reason == "boom"
    assert h.account.discovery_state == CloudDiscoveryState.FAILED


def test_partial_resource_failure_does_not_abort_run() -> None:
    class HalfFailingReader:
        def get(self, tenant_id, asset_id):
            return None

    h = Harness(resources=(_resource("i-1"), _resource("i-2")))

    original_register_asset = h.asset_inventory_service.register_asset
    calls = {"n": 0}

    def flaky_register(cmd):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient failure")
        return original_register_asset(cmd)

    h.asset_inventory_service.register_asset = flaky_register  # type: ignore[method-assign]

    outcome = h.service.start_discovery(h.start_cmd(), h.account)

    assert outcome.record.status.value == "completed"
    assert outcome.record.failed_count == 1
    assert outcome.record.discovered_count == 1


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def test_account_mismatch_raises() -> None:
    h = Harness()
    other_account = CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=h.tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="other-account",
        tags=CloudTagSet(),
        now=NOW,
    )

    with pytest.raises(AccountMismatchError):
        h.service.start_discovery(h.start_cmd(), other_account)


def test_unknown_provider_raises() -> None:
    h = Harness()
    with pytest.raises(UnsupportedProviderError):
        h.service.start_discovery(h.start_cmd(provider_id=ProviderId.generate()), h.account)


def test_disabled_provider_raises() -> None:
    h = Harness(provider_enabled=False)
    with pytest.raises(ProviderNotEnabledError):
        h.service.start_discovery(h.start_cmd(), h.account)


def test_missing_discovery_capability_raises() -> None:
    h = Harness(with_discovery_capability=False)
    with pytest.raises(MissingDiscoveryCapabilityError):
        h.service.start_discovery(h.start_cmd(), h.account)


def test_missing_credential_raises() -> None:
    h = Harness()
    h.credential_association.detach(h.tenant_id, NOW)
    h.credential_registry.release(h.credential_association)

    with pytest.raises(CredentialNotAttachedError):
        h.service.start_discovery(h.start_cmd(), h.account)


def test_no_registered_discovery_provider_raises() -> None:
    h = Harness()
    h.discovery_providers.clear()

    with pytest.raises(NoDiscoveryProviderRegisteredError):
        h.service.start_discovery(h.start_cmd(), h.account)


def test_duplicate_discovery_job_raises() -> None:
    h = Harness(resources=(_resource("i-1"),))
    # simulate an in-progress job that hasn't completed by registering directly
    lingering_job = CloudDiscoveryJob.start(
        job_id=DiscoveryJobId.generate(),
        tenant_id=h.tenant_id,
        account_id=h.account.account_id,
        provider_id=h.provider.provider_id,
        window=WINDOW,
        now=NOW,
    )
    h.job_registry.register(lingering_job)

    with pytest.raises(DuplicateDiscoveryJobError):
        h.service.start_discovery(h.start_cmd(), h.account)


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------


def test_cancel_in_progress_job() -> None:
    h = Harness()
    job = CloudDiscoveryJob.start(
        job_id=DiscoveryJobId.generate(),
        tenant_id=h.tenant_id,
        account_id=h.account.account_id,
        provider_id=h.provider.provider_id,
        window=WINDOW,
        now=NOW,
    )
    h.job_registry.register(job)

    cancelled = h.service.cancel_discovery(CancelDiscoveryCommand(tenant_id=h.tenant_id, job_id=job.job_id))

    assert cancelled.job_id == str(job.job_id)
    assert job.status.value == "cancelled"
    assert h.job_registry.has_active_job(h.tenant_id, h.account.account_id, h.provider.provider_id) is False


def test_cancel_unknown_job_raises() -> None:
    h = Harness()
    with pytest.raises(DiscoveryJobNotFoundError):
        h.service.cancel_discovery(
            CancelDiscoveryCommand(tenant_id=h.tenant_id, job_id=DiscoveryJobId.generate())
        )


# ---------------------------------------------------------------------------
# refresh / organization / batch
# ---------------------------------------------------------------------------


def test_refresh_discovery_creates_new_job() -> None:
    h = Harness(resources=(_resource("i-1"),))
    first = h.service.start_discovery(h.start_cmd(), h.account)

    refreshed = h.service.refresh_discovery(
        RefreshDiscoveryCommand(
            tenant_id=h.tenant_id, job_id=DiscoveryJobId(UUID(first.record.job_id)), window=WINDOW
        ),
        h.account,
    )

    assert refreshed.record.job_id != first.record.job_id
    assert refreshed.record.status.value == "completed"


def test_refresh_unknown_job_raises() -> None:
    h = Harness()
    with pytest.raises(DiscoveryJobNotFoundError):
        h.service.refresh_discovery(
            RefreshDiscoveryCommand(
                tenant_id=h.tenant_id, job_id=DiscoveryJobId.generate(), window=WINDOW
            ),
            h.account,
        )


def test_discover_organization_runs_all_accounts() -> None:
    h = Harness(resources=(_resource("i-1"),))
    other_account = CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=h.tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="second-account",
        tags=CloudTagSet(),
        now=NOW,
    )
    h.credential_registry.register(
        CredentialAssociation.attach(
            association_id=CredentialAssociationId.generate(),
            tenant_id=h.tenant_id,
            account_id=other_account.account_id,
            provider_id=h.provider.provider_id,
            reference=CloudCredentialReference(credential_id="cred-2", credential_type="role_arn"),
            now=NOW,
        )
    )
    accounts = {str(h.account.account_id): h.account, str(other_account.account_id): other_account}

    result = h.service.discover_organization(
        DiscoverOrganizationCommand(
            tenant_id=h.tenant_id,
            provider_id=h.provider.provider_id,
            account_ids=(h.account.account_id, other_account.account_id),
            window=WINDOW,
        ),
        accounts,
    )

    assert result.status == BatchDiscoveryStatus.SUCCEEDED
    assert result.succeeded_count == 2


def test_batch_discovery_partial_failure() -> None:
    h = Harness(resources=(_resource("i-1"),))
    other_account = CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=h.tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="no-credential-account",
        tags=CloudTagSet(),
        now=NOW,
    )  # no credential attached -> will fail validation
    accounts = {str(h.account.account_id): h.account, str(other_account.account_id): other_account}
    commands = (
        h.start_cmd(),
        h.start_cmd(account_id=other_account.account_id),
    )

    result = h.service.register_batch(
        BatchDiscoveryCommand(tenant_id=h.tenant_id, commands=commands), accounts
    )

    assert result.status == BatchDiscoveryStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


def test_batch_discovery_empty_raises() -> None:
    h = Harness()
    with pytest.raises(EmptyBatchDiscoveryError):
        h.service.register_batch(BatchDiscoveryCommand(tenant_id=h.tenant_id, commands=()), {})


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------


def test_get_discovery_status_returns_none_when_missing() -> None:
    h = Harness()
    result = h.service.get_discovery_status(
        GetDiscoveryStatusQuery(tenant_id=h.tenant_id, job_id=DiscoveryJobId.generate())
    )
    assert result is None


def test_get_discovery_status_after_run() -> None:
    h = Harness(resources=(_resource("i-1"),))
    outcome = h.service.start_discovery(h.start_cmd(), h.account)
    job_id = DiscoveryJobId(UUID(outcome.record.job_id))

    status = h.service.get_discovery_status(GetDiscoveryStatusQuery(tenant_id=h.tenant_id, job_id=job_id))

    assert status is not None
    assert status.status.value == "completed"


def test_list_discovery_jobs() -> None:
    h = Harness(resources=(_resource("i-1"),))
    h.service.start_discovery(h.start_cmd(), h.account)

    jobs = h.service.list_discovery_jobs(ListDiscoveryJobsQuery(tenant_id=h.tenant_id))
    assert len(jobs) == 1


def test_list_discovered_assets() -> None:
    h = Harness(resources=(_resource("i-1"), _resource("i-2")))
    outcome = h.service.start_discovery(h.start_cmd(), h.account)
    job_id = DiscoveryJobId(UUID(outcome.record.job_id))

    asset_ids = h.service.list_discovered_assets(
        ListDiscoveredAssetsQuery(tenant_id=h.tenant_id, job_id=job_id)
    )
    assert len(asset_ids) == 2


def test_discovery_statistics() -> None:
    h = Harness(resources=(_resource("i-1"), _resource("i-2")))
    h.service.start_discovery(h.start_cmd(), h.account)

    stats = h.service.discovery_statistics(DiscoveryStatisticsQuery(tenant_id=h.tenant_id))

    assert stats.total_jobs == 1
    assert stats.completed_jobs == 1
    assert stats.total_assets_discovered == 2


# ---------------------------------------------------------------------------
# tenant isolation
# ---------------------------------------------------------------------------


def test_jobs_are_tenant_isolated() -> None:
    h = Harness(resources=(_resource("i-1"),))
    h.service.start_discovery(h.start_cmd(), h.account)

    other_tenant_jobs = h.service.list_discovery_jobs(ListDiscoveryJobsQuery(tenant_id=TenantId.generate()))
    assert other_tenant_jobs == ()


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_discovery_started_outcome_is_frozen() -> None:
    h = Harness()
    outcome = h.service.start_discovery(h.start_cmd(), h.account)
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.record = None  # type: ignore[misc]


def test_batch_discovery_result_is_frozen() -> None:
    h = Harness(resources=(_resource("i-1"),))
    result = h.service.register_batch(
        BatchDiscoveryCommand(tenant_id=h.tenant_id, commands=(h.start_cmd(),)),
        {str(h.account.account_id): h.account},
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = BatchDiscoveryStatus.FAILED  # type: ignore[misc]

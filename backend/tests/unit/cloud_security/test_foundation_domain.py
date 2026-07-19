"""Unit tests for M26 Cloud Security foundation domain."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.entities import AvailabilityZone, CloudRegion
from redforge.domain.cloud_security.events import (
    CloudAccountDiscovered,
    CloudProviderDisabled,
    CloudProviderRegistered,
    CloudProviderUpdated,
)
from redforge.domain.cloud_security.exceptions import (
    CloudProviderDisabledError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    AccountSyncState,
    CloudAccountType,
    CloudProviderStatus,
    CloudProviderType,
    CredentialRef,
    DiscoveryConfig,
    OrganizationId,
    SyncStatus,
)


def test_register_cloud_provider_emits_event() -> None:
    provider = CloudProvider.register(
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        provider_type=CloudProviderType.AWS,
        display_name="Prod AWS",
    )
    events = provider.pop_events()
    assert provider.status is CloudProviderStatus.ACTIVE
    assert len(events) == 1
    assert isinstance(events[0], CloudProviderRegistered)
    assert events[0].provider_type == "AWS"


def test_update_and_disable_cloud_provider() -> None:
    provider = CloudProvider.register(
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        provider_type=CloudProviderType.AZURE,
        display_name="Azure",
    )
    provider.pop_events()
    provider.update(display_name="Azure West")
    assert isinstance(provider.pop_events()[0], CloudProviderUpdated)
    provider.disable()
    assert provider.status is CloudProviderStatus.DISABLED
    assert isinstance(provider.pop_events()[0], CloudProviderDisabled)
    with pytest.raises(CloudProviderDisabledError):
        provider.update(display_name="Nope")


def test_discovery_config_validation() -> None:
    with pytest.raises(ValueError):
        DiscoveryConfig(polling_interval_seconds=10)


def test_account_sync_failed_requires_error() -> None:
    with pytest.raises(ValueError):
        AccountSyncState(status=SyncStatus.FAILED)


def test_register_cloud_account_with_region() -> None:
    region = CloudRegion(
        region_code="us-east-1",
        display_name="US East",
        availability_zones=(AvailabilityZone(name="us-east-1a", region_code="us-east-1"),),
    )
    account = CloudAccount.register(
        cloud_provider_id=CloudProvider.register(
            organization_id=OrganizationId("01HXORG0000000000000000001"),
            provider_type=CloudProviderType.GCP,
            display_name="GCP",
        ).id,
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        external_id="123456789012",
        display_name="Billing",
        account_type=CloudAccountType.STANDALONE,
        credential_ref=CredentialRef(reference_id="cred-1"),
        regions=(region,),
        now=datetime.now(UTC),
    )
    events = account.pop_events()
    assert isinstance(events[0], CloudAccountDiscovered)
    assert account.sync_state.status is SyncStatus.PENDING


def test_cloud_account_rejects_blank_external_id() -> None:
    with pytest.raises(InvalidCloudArgumentError):
        CloudAccount.register(
            cloud_provider_id=CloudProvider.register(
                organization_id=OrganizationId("01HXORG0000000000000000001"),
                provider_type=CloudProviderType.AWS,
                display_name="AWS",
            ).id,
            organization_id=OrganizationId("01HXORG0000000000000000001"),
            external_id="  ",
            display_name="x",
            account_type=CloudAccountType.ROOT,
            credential_ref=CredentialRef(reference_id="cred-1"),
        )


def test_availability_zone_must_match_region() -> None:
    with pytest.raises(ValueError):
        CloudRegion(
            region_code="us-west-2",
            display_name="West",
            availability_zones=(AvailabilityZone(name="us-east-1a", region_code="us-east-1"),),
        )

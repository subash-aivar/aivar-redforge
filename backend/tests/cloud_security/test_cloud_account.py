from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.domain.aggregates.cloud_account import CloudAccount
from cloud_security.domain.events.cloud_account_events import (
    CloudAccountRegistered,
    CredentialLinked,
    DiscoveryCompleted,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    CredentialAlreadyLinkedError,
    EmptyDisplayNameError,
    InvalidCloudAccountTransition,
    InvalidDiscoveryTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.cloud_credential_reference import (
    CloudCredentialReference,
)
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
from cloud_security.domain.value_objects.enums import (
    CloudConnectionStatus,
    CloudDiscoveryState,
    CloudPlatformType,
)
from cloud_security.domain.value_objects.identifiers import AccountId, ProviderId, TenantId

NOW = datetime.now(UTC)


def _register(**overrides) -> CloudAccount:
    defaults = {
        "account_id": AccountId.generate(),
        "tenant_id": TenantId.generate(),
        "provider_id": ProviderId.generate(),
        "platform_type": CloudPlatformType.AWS,
        "display_name": "prod-account",
        "tags": CloudTagSet(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudAccount.register(**defaults)


def test_register_emits_event_and_sets_defaults() -> None:
    account = _register()
    assert account.connection_status == CloudConnectionStatus.PENDING
    assert account.discovery_state == CloudDiscoveryState.NOT_STARTED
    assert account.credential_ref is None

    events = account.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], CloudAccountRegistered)
    assert events[0].platform_type == CloudPlatformType.AWS

    # pop_events clears the pending list
    assert account.pop_events() == []


def test_register_rejects_empty_display_name() -> None:
    with pytest.raises(EmptyDisplayNameError):
        _register(display_name="   ")


def test_link_credential_succeeds_once() -> None:
    account = _register()
    account.pop_events()
    tenant_id = account.tenant_id
    ref = CloudCredentialReference(credential_id="cred-1", credential_type="role_arn")

    account.link_credential(tenant_id, ref, NOW)

    assert account.credential_ref is ref
    events = account.pop_events()
    assert isinstance(events[0], CredentialLinked)


def test_link_credential_twice_raises() -> None:
    account = _register()
    tenant_id = account.tenant_id
    ref = CloudCredentialReference(credential_id="cred-1", credential_type="role_arn")
    account.link_credential(tenant_id, ref, NOW)

    with pytest.raises(CredentialAlreadyLinkedError):
        account.link_credential(tenant_id, ref, NOW)


def test_link_credential_wrong_tenant_raises() -> None:
    account = _register()
    ref = CloudCredentialReference(credential_id="cred-1", credential_type="role_arn")

    with pytest.raises(TenantMismatch):
        account.link_credential(TenantId.generate(), ref, NOW)


def test_connection_lifecycle() -> None:
    account = _register()
    tenant_id = account.tenant_id

    account.mark_connected(tenant_id)
    assert account.connection_status == CloudConnectionStatus.CONNECTED

    account.mark_disconnected(tenant_id)
    assert account.connection_status == CloudConnectionStatus.DISCONNECTED

    account.mark_connected(tenant_id)
    account.revoke(tenant_id)
    assert account.connection_status == CloudConnectionStatus.REVOKED


def test_connection_invalid_transition_raises() -> None:
    account = _register()
    tenant_id = account.tenant_id

    with pytest.raises(InvalidCloudAccountTransition):
        account.mark_disconnected(tenant_id)  # can't disconnect from PENDING


def test_discovery_lifecycle() -> None:
    account = _register()
    tenant_id = account.tenant_id
    account.pop_events()

    account.start_discovery(tenant_id)
    assert account.discovery_state == CloudDiscoveryState.IN_PROGRESS

    account.complete_discovery(tenant_id, 42, NOW)
    assert account.discovery_state == CloudDiscoveryState.COMPLETED

    events = account.pop_events()
    assert isinstance(events[0], DiscoveryCompleted)
    assert events[0].discovered_asset_count == 42


def test_discovery_can_restart_after_failure() -> None:
    account = _register()
    tenant_id = account.tenant_id
    account.start_discovery(tenant_id)
    account.fail_discovery(tenant_id)
    assert account.discovery_state == CloudDiscoveryState.FAILED

    account.start_discovery(tenant_id)
    assert account.discovery_state == CloudDiscoveryState.IN_PROGRESS


def test_complete_discovery_without_starting_raises() -> None:
    account = _register()
    with pytest.raises(InvalidDiscoveryTransition):
        account.complete_discovery(account.tenant_id, 1, NOW)


def test_complete_discovery_rejects_negative_count() -> None:
    account = _register()
    account.start_discovery(account.tenant_id)
    with pytest.raises(ValueError, match="discovered_asset_count"):
        account.complete_discovery(account.tenant_id, -1, NOW)

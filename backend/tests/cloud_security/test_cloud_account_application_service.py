from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.application.commands.cloud_account_commands import (
    CompleteCloudDiscoveryCommand,
    LinkCloudCredentialCommand,
    RegisterCloudAccountCommand,
    StartCloudDiscoveryCommand,
)
from cloud_security.application.exceptions import InvalidDisplayNameError, UnsupportedProviderError
from cloud_security.application.registry.in_memory_cloud_provider_registry import (
    InMemoryCloudProviderRegistry,
)
from cloud_security.application.services.cloud_account_application_service import (
    CloudAccountApplicationService,
)
from cloud_security.domain.aggregates.cloud_account import CloudAccount
from cloud_security.domain.value_objects.cloud_credential_reference import (
    CloudCredentialReference,
)
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
from cloud_security.domain.value_objects.enums import CloudConnectionStatus, CloudPlatformType
from cloud_security.domain.value_objects.identifiers import AccountId, ProviderId, TenantId

from .test_in_memory_cloud_provider_registry import FakeCloudProvider


def _registry_with(*platform_types: CloudPlatformType) -> InMemoryCloudProviderRegistry:
    registry = InMemoryCloudProviderRegistry()
    for platform_type in platform_types:
        registry.register(FakeCloudProvider(platform_type))
    return registry


def _command(**overrides) -> RegisterCloudAccountCommand:
    defaults = {
        "tenant_id": TenantId.generate(),
        "provider_id": ProviderId.generate(),
        "platform_type": CloudPlatformType.AWS,
        "display_name": "prod-account",
    }
    defaults.update(overrides)
    return RegisterCloudAccountCommand(**defaults)


def test_register_account_returns_dto() -> None:
    service = CloudAccountApplicationService(_registry_with(CloudPlatformType.AWS))

    dto = service.register_account(_command())

    assert dto.platform_type == CloudPlatformType.AWS
    assert dto.connection_status == CloudConnectionStatus.PENDING
    assert dto.has_linked_credential is False


def test_register_account_unsupported_provider_raises() -> None:
    service = CloudAccountApplicationService(InMemoryCloudProviderRegistry())

    with pytest.raises(UnsupportedProviderError):
        service.register_account(_command())


def test_register_account_rejects_empty_display_name() -> None:
    service = CloudAccountApplicationService(_registry_with(CloudPlatformType.AWS))

    with pytest.raises(InvalidDisplayNameError):
        service.register_account(_command(display_name="  "))


def _registered_account(tenant_id: TenantId) -> CloudAccount:
    return CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="prod-account",
        tags=CloudTagSet(),
        now=datetime.now(UTC),
    )


def test_link_credential_returns_updated_dto() -> None:
    service = CloudAccountApplicationService(_registry_with(CloudPlatformType.AWS))
    tenant_id = TenantId.generate()
    account = _registered_account(tenant_id)
    cmd = LinkCloudCredentialCommand(
        tenant_id=tenant_id, credential_id="cred-1", credential_type="role_arn"
    )
    ref = CloudCredentialReference(credential_id="cred-1", credential_type="role_arn")

    dto = service.link_credential(account, cmd, ref)

    assert dto.has_linked_credential is True


def test_discovery_lifecycle_through_service() -> None:
    service = CloudAccountApplicationService(_registry_with(CloudPlatformType.AWS))
    tenant_id = TenantId.generate()
    account = _registered_account(tenant_id)

    dto = service.start_discovery(account, StartCloudDiscoveryCommand(tenant_id=tenant_id))
    assert dto.discovery_state.value == "in_progress"

    dto = service.complete_discovery(
        account, CompleteCloudDiscoveryCommand(tenant_id=tenant_id, discovered_asset_count=7)
    )
    assert dto.discovery_state.value == "completed"

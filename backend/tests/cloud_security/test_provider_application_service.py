from __future__ import annotations

import dataclasses
from uuid import UUID

import pytest

from cloud_security.application.commands.provider_commands import (
    BatchProviderCommand,
    DisableProviderCommand,
    EnableProviderCommand,
    RegisterProviderCommand,
    RemoveProviderCommand,
    UpdateProviderCommand,
)
from cloud_security.application.dtos.provider_outcomes import BatchProviderStatus
from cloud_security.application.exceptions import (
    DuplicateProviderForPlatformError,
    EmptyBatchProviderError,
    InvalidDisplayNameError,
    InvalidProviderError,
    ProviderNotFoundError,
)
from cloud_security.application.queries.provider_queries import (
    GetProviderQuery,
    ListEnabledProvidersQuery,
    ListProvidersByCapabilityQuery,
    ListProvidersByPlatformQuery,
    ListProvidersQuery,
)
from cloud_security.application.registry.in_memory_provider_registry import (
    InMemoryProviderRegistry,
)
from cloud_security.application.services.provider_application_service import (
    ProviderApplicationService,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidProviderTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import (
    CloudPlatformType,
    ProviderCapability,
    ProviderStatus,
)
from cloud_security.domain.value_objects.identifiers import ProviderId, TenantId
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet


def _provider_id(outcome) -> ProviderId:
    return ProviderId(UUID(outcome.record.provider_id))


def _service(registry=None):
    return ProviderApplicationService(provider_registry=registry or InMemoryProviderRegistry())


def _command(**overrides) -> RegisterProviderCommand:
    defaults = {
        "tenant_id": TenantId.generate(),
        "platform_type": CloudPlatformType.AWS,
        "display_name": "aws-primary",
        "capabilities": ProviderCapabilitySet(),
    }
    defaults.update(overrides)
    return RegisterProviderCommand(**defaults)


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------


def test_register_provider_returns_dto() -> None:
    service = _service()

    outcome = service.register_provider(_command())

    assert outcome.record.platform_type == CloudPlatformType.AWS
    assert outcome.record.status == ProviderStatus.DISABLED


def test_register_provider_rejects_empty_display_name() -> None:
    service = _service()
    with pytest.raises(InvalidDisplayNameError):
        service.register_provider(_command(display_name="  "))


def test_register_provider_rejects_unsupported_platform() -> None:
    service = _service()
    with pytest.raises(InvalidProviderError):
        service.register_provider(_command(platform_type=CloudPlatformType.OTHER))


def test_register_duplicate_platform_for_tenant_raises() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    service.register_provider(_command(tenant_id=tenant_id))

    with pytest.raises(DuplicateProviderForPlatformError):
        service.register_provider(_command(tenant_id=tenant_id))


# ---------------------------------------------------------------------------
# enable / disable / remove
# ---------------------------------------------------------------------------


def test_enable_then_disable_cycle() -> None:
    registry = InMemoryProviderRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    provider_id = _provider_id(service.register_provider(_command(tenant_id=tenant_id)))

    enabled = service.enable_provider(tenant_id, provider_id, EnableProviderCommand(tenant_id=tenant_id))
    assert enabled.record.status == ProviderStatus.ENABLED

    disabled = service.disable_provider(
        tenant_id, provider_id, DisableProviderCommand(tenant_id=tenant_id)
    )
    assert disabled.record.status == ProviderStatus.DISABLED


def test_enable_unknown_provider_raises() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    with pytest.raises(ProviderNotFoundError):
        service.enable_provider(
            tenant_id, ProviderId.generate(), EnableProviderCommand(tenant_id=tenant_id)
        )


def test_enable_twice_raises() -> None:
    registry = InMemoryProviderRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    outcome = service.register_provider(_command(tenant_id=tenant_id))
    provider_id = _provider_id(outcome)
    service.enable_provider(tenant_id, provider_id, EnableProviderCommand(tenant_id=tenant_id))

    with pytest.raises(InvalidProviderTransition):
        service.enable_provider(tenant_id, provider_id, EnableProviderCommand(tenant_id=tenant_id))


def test_remove_provider() -> None:
    registry = InMemoryProviderRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    outcome = service.register_provider(_command(tenant_id=tenant_id))
    provider_id = _provider_id(outcome)

    removed = service.remove_provider(tenant_id, provider_id, RemoveProviderCommand(tenant_id=tenant_id))

    assert removed.provider_id == str(provider_id)
    stored = registry.get(tenant_id, provider_id)
    assert stored.status == ProviderStatus.REMOVED


def test_wrong_tenant_command_raises_tenant_mismatch() -> None:
    registry = InMemoryProviderRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    outcome = service.register_provider(_command(tenant_id=tenant_id))
    provider_id = _provider_id(outcome)
    other_tenant = TenantId.generate()

    with pytest.raises(TenantMismatch):
        service.enable_provider(tenant_id, provider_id, EnableProviderCommand(tenant_id=other_tenant))


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


def test_update_provider_display_name() -> None:
    registry = InMemoryProviderRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()
    provider_id = _provider_id(service.register_provider(_command(tenant_id=tenant_id)))

    outcome = service.update_provider(
        tenant_id, provider_id, UpdateProviderCommand(tenant_id=tenant_id, display_name="renamed")
    )

    assert outcome.record.display_name == "renamed"


def test_update_unknown_provider_raises() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    with pytest.raises(ProviderNotFoundError):
        service.update_provider(
            tenant_id, ProviderId.generate(), UpdateProviderCommand(tenant_id=tenant_id)
        )


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------


def test_batch_register_all_succeed() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    commands = (
        _command(tenant_id=tenant_id, platform_type=CloudPlatformType.AWS),
        _command(tenant_id=tenant_id, platform_type=CloudPlatformType.AZURE),
    )

    result = service.register_batch(BatchProviderCommand(tenant_id=tenant_id, commands=commands))

    assert result.status == BatchProviderStatus.SUCCEEDED
    assert result.succeeded_count == 2
    assert result.failed_count == 0


def test_batch_register_empty_raises() -> None:
    service = _service()
    with pytest.raises(EmptyBatchProviderError):
        service.register_batch(BatchProviderCommand(tenant_id=TenantId.generate(), commands=()))


def test_batch_register_partial_failure_on_duplicate_platform() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    commands = (
        _command(tenant_id=tenant_id, platform_type=CloudPlatformType.AWS),
        _command(tenant_id=tenant_id, platform_type=CloudPlatformType.AWS),  # duplicate
    )

    result = service.register_batch(BatchProviderCommand(tenant_id=tenant_id, commands=commands))

    assert result.status == BatchProviderStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


def test_batch_register_all_fail() -> None:
    service = _service()
    tenant_id = TenantId.generate()
    commands = (
        _command(tenant_id=tenant_id, platform_type=CloudPlatformType.OTHER),
        _command(tenant_id=tenant_id, display_name=""),
    )

    result = service.register_batch(BatchProviderCommand(tenant_id=tenant_id, commands=commands))

    assert result.status == BatchProviderStatus.FAILED
    assert result.succeeded_count == 0
    assert result.failed_count == 2


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------


def test_get_provider_returns_none_when_missing() -> None:
    service = _service()
    result = service.get_provider(
        GetProviderQuery(tenant_id=TenantId.generate(), provider_id=ProviderId.generate())
    )
    assert result is None


def test_list_providers_and_by_platform_and_enabled_and_capability() -> None:
    registry = InMemoryProviderRegistry()
    service = _service(registry)
    tenant_id = TenantId.generate()

    aws_outcome = service.register_provider(
        _command(
            tenant_id=tenant_id,
            platform_type=CloudPlatformType.AWS,
            capabilities=ProviderCapabilitySet(capabilities=(ProviderCapability.DISCOVERY,)),
        )
    )
    service.register_provider(_command(tenant_id=tenant_id, platform_type=CloudPlatformType.AZURE))

    assert len(service.list_providers(ListProvidersQuery(tenant_id=tenant_id))) == 2
    assert len(
        service.list_providers_by_platform(
            ListProvidersByPlatformQuery(tenant_id=tenant_id, platform_type=CloudPlatformType.AWS)
        )
    ) == 1

    aws_provider_id = _provider_id(aws_outcome)
    service.enable_provider(tenant_id, aws_provider_id, EnableProviderCommand(tenant_id=tenant_id))
    enabled = service.list_enabled_providers(ListEnabledProvidersQuery(tenant_id=tenant_id))
    assert len(enabled) == 1
    assert enabled[0].platform_type == CloudPlatformType.AWS

    by_capability = service.list_providers_by_capability(
        ListProvidersByCapabilityQuery(tenant_id=tenant_id, capability=ProviderCapability.DISCOVERY)
    )
    assert len(by_capability) == 1


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_provider_registered_outcome_is_frozen() -> None:
    service = _service()
    outcome = service.register_provider(_command())
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.record = None  # type: ignore[misc]


def test_batch_provider_result_is_frozen() -> None:
    service = _service()
    result = service.register_batch(
        BatchProviderCommand(tenant_id=TenantId.generate(), commands=(_command(),))
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = BatchProviderStatus.FAILED  # type: ignore[misc]

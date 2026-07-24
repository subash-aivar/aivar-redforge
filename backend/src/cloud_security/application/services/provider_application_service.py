"""ProviderApplicationService — the canonical entrypoint for every
Cloud Provider Framework operation (M45C).

Owns provider registration, capability discovery, selection, lifecycle
(enable/disable/remove), and compatibility validation — nothing else.
No cloud SDK calls, no discovery, no scanning. `CloudProviderRegistration`
remains the single aggregate; this service only validates input,
delegates to the aggregate's own lifecycle methods, and returns
immutable DTOs. This service holds no state between calls beyond its
injected `IProviderRegistry`, so it stays stateless — the registry
itself is the framework's only stateful component, by design."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.dtos.provider_outcomes import (
    BatchProviderFailure,
    BatchProviderResult,
    BatchProviderStatus,
    ProviderDisabled,
    ProviderEnabled,
    ProviderRegistered,
    ProviderRemoved,
    ProviderUpdated,
)
from cloud_security.application.dtos.provider_record import ProviderRecord
from cloud_security.application.exceptions import ProviderNotFoundError
from cloud_security.application.services import provider_validation
from cloud_security.domain.aggregates.cloud_provider_registration import (
    CloudProviderRegistration,
)
from cloud_security.domain.value_objects.identifiers import ProviderId

if TYPE_CHECKING:
    from cloud_security.application.commands.provider_commands import (
        BatchProviderCommand,
        DisableProviderCommand,
        EnableProviderCommand,
        RegisterProviderCommand,
        RemoveProviderCommand,
        UpdateProviderCommand,
    )
    from cloud_security.application.ports.i_provider_registry import IProviderRegistry
    from cloud_security.application.queries.provider_queries import (
        GetProviderQuery,
        ListEnabledProvidersQuery,
        ListProvidersByCapabilityQuery,
        ListProvidersByPlatformQuery,
        ListProvidersQuery,
    )
    from cloud_security.domain.value_objects.identifiers import TenantId


def _to_record(registration: CloudProviderRegistration) -> ProviderRecord:
    return ProviderRecord(
        provider_id=str(registration.provider_id),
        tenant_id=str(registration.tenant_id),
        platform_type=registration.platform_type,
        display_name=registration.display_name,
        capabilities=registration.capabilities,
        status=registration.status,
        registered_at=registration.registered_at,
        updated_at=registration.updated_at,
    )


class ProviderApplicationService:
    def __init__(self, provider_registry: IProviderRegistry) -> None:
        self._registry = provider_registry

    # -- commands ------------------------------------------------------

    def register_provider(self, cmd: RegisterProviderCommand) -> ProviderRegistered:
        provider_validation.validate_display_name(cmd.display_name)
        provider_validation.validate_platform_supported(cmd.platform_type)
        registration = CloudProviderRegistration.register(
            provider_id=ProviderId.generate(),
            tenant_id=cmd.tenant_id,
            platform_type=cmd.platform_type,
            display_name=cmd.display_name,
            capabilities=cmd.capabilities,
            now=datetime.now(UTC),
        )
        self._registry.register(registration)
        return ProviderRegistered(record=_to_record(registration))

    def register_batch(self, cmd: BatchProviderCommand) -> BatchProviderResult:
        provider_validation.validate_batch_not_empty(cmd.commands)

        registered: list[ProviderRegistered] = []
        failures: list[BatchProviderFailure] = []
        for index, register_cmd in enumerate(cmd.commands):
            try:
                registered.append(self.register_provider(register_cmd))
            except Exception as exc:
                failures.append(
                    BatchProviderFailure(
                        index=index, error_type=type(exc).__name__, message=str(exc)
                    )
                )

        if not failures:
            status = BatchProviderStatus.SUCCEEDED
        elif not registered:
            status = BatchProviderStatus.FAILED
        else:
            status = BatchProviderStatus.PARTIALLY_SUCCEEDED

        return BatchProviderResult(
            status=status, registered=tuple(registered), failures=tuple(failures)
        )

    def update_provider(
        self, tenant_id: TenantId, provider_id: ProviderId, cmd: UpdateProviderCommand
    ) -> ProviderUpdated:
        registration = self._require(tenant_id, provider_id)
        registration.update(
            tenant_id=cmd.tenant_id,
            now=datetime.now(UTC),
            display_name=cmd.display_name,
            capabilities=cmd.capabilities,
        )
        return ProviderUpdated(record=_to_record(registration))

    def enable_provider(
        self, tenant_id: TenantId, provider_id: ProviderId, cmd: EnableProviderCommand
    ) -> ProviderEnabled:
        registration = self._require(tenant_id, provider_id)
        registration.enable(cmd.tenant_id, datetime.now(UTC))
        return ProviderEnabled(record=_to_record(registration))

    def disable_provider(
        self, tenant_id: TenantId, provider_id: ProviderId, cmd: DisableProviderCommand
    ) -> ProviderDisabled:
        registration = self._require(tenant_id, provider_id)
        registration.disable(cmd.tenant_id, datetime.now(UTC))
        return ProviderDisabled(record=_to_record(registration))

    def remove_provider(
        self, tenant_id: TenantId, provider_id: ProviderId, cmd: RemoveProviderCommand
    ) -> ProviderRemoved:
        registration = self._require(tenant_id, provider_id)
        registration.remove(cmd.tenant_id, datetime.now(UTC))
        return ProviderRemoved(
            provider_id=str(registration.provider_id), tenant_id=str(registration.tenant_id)
        )

    def _require(self, tenant_id: TenantId, provider_id: ProviderId) -> CloudProviderRegistration:
        registration = self._registry.get(tenant_id, provider_id)
        if registration is None:
            raise ProviderNotFoundError(provider_id)
        return registration

    # -- queries ---------------------------------------------------------

    def get_provider(self, query: GetProviderQuery) -> ProviderRecord | None:
        registration = self._registry.get(query.tenant_id, query.provider_id)
        return _to_record(registration) if registration is not None else None

    def list_providers(self, query: ListProvidersQuery) -> tuple[ProviderRecord, ...]:
        return tuple(_to_record(r) for r in self._registry.list(query.tenant_id))

    def list_providers_by_platform(
        self, query: ListProvidersByPlatformQuery
    ) -> tuple[ProviderRecord, ...]:
        return tuple(
            _to_record(r)
            for r in self._registry.list_by_platform(query.tenant_id, query.platform_type)
        )

    def list_enabled_providers(
        self, query: ListEnabledProvidersQuery
    ) -> tuple[ProviderRecord, ...]:
        return tuple(_to_record(r) for r in self._registry.list_enabled(query.tenant_id))

    def list_providers_by_capability(
        self, query: ListProvidersByCapabilityQuery
    ) -> tuple[ProviderRecord, ...]:
        return tuple(
            _to_record(r)
            for r in self._registry.list_by_capability(query.tenant_id, query.capability)
        )

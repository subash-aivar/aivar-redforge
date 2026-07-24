"""CloudAccountApplicationService — application-layer orchestration for
`CloudAccount` commands (M45A).

Scaffolding only, per this milestone's scope: validates the command,
confirms the target platform has a registered `ICloudProvider`, then
delegates to the aggregate's own lifecycle methods and returns a
read-only DTO. No persistence — there is no repository port in this
milestone, so callers own the `CloudAccount` instance across calls
(the same "no persistence" discipline as `siem_search`/`siem_analytics`,
applied here to the write side because infrastructure is out of scope
for M45A specifically, not because this context is read-only)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.dtos.cloud_account_dto import CloudAccountDto
from cloud_security.application.exceptions import UnsupportedProviderError
from cloud_security.application.services import command_validation
from cloud_security.domain.aggregates.cloud_account import CloudAccount
from cloud_security.domain.value_objects.identifiers import AccountId

if TYPE_CHECKING:
    from cloud_security.application.commands.cloud_account_commands import (
        CompleteCloudDiscoveryCommand,
        LinkCloudCredentialCommand,
        RegisterCloudAccountCommand,
        StartCloudDiscoveryCommand,
    )
    from cloud_security.application.ports.i_cloud_provider_registry import (
        ICloudProviderRegistry,
    )
    from cloud_security.domain.value_objects.cloud_credential_reference import (
        CloudCredentialReference,
    )


def _to_dto(account: CloudAccount) -> CloudAccountDto:
    return CloudAccountDto(
        account_id=str(account.account_id),
        tenant_id=str(account.tenant_id),
        provider_id=str(account.provider_id),
        platform_type=account.platform_type,
        display_name=account.display_name,
        connection_status=account.connection_status,
        discovery_state=account.discovery_state,
        has_linked_credential=account.credential_ref is not None,
        registered_at=account.registered_at,
    )


class CloudAccountApplicationService:
    def __init__(self, provider_registry: ICloudProviderRegistry) -> None:
        self._registry = provider_registry

    def register_account(self, cmd: RegisterCloudAccountCommand) -> CloudAccountDto:
        command_validation.validate_display_name(cmd.display_name)
        if not self._registry.is_registered(cmd.platform_type):
            raise UnsupportedProviderError(cmd.platform_type)
        account = CloudAccount.register(
            account_id=AccountId.generate(),
            tenant_id=cmd.tenant_id,
            provider_id=cmd.provider_id,
            platform_type=cmd.platform_type,
            display_name=cmd.display_name,
            tags=cmd.tags,
            now=datetime.now(UTC),
        )
        return _to_dto(account)

    def link_credential(
        self,
        account: CloudAccount,
        cmd: LinkCloudCredentialCommand,
        credential_ref: CloudCredentialReference,
    ) -> CloudAccountDto:
        account.link_credential(cmd.tenant_id, credential_ref, datetime.now(UTC))
        return _to_dto(account)

    def start_discovery(
        self, account: CloudAccount, cmd: StartCloudDiscoveryCommand
    ) -> CloudAccountDto:
        account.start_discovery(cmd.tenant_id)
        return _to_dto(account)

    def complete_discovery(
        self, account: CloudAccount, cmd: CompleteCloudDiscoveryCommand
    ) -> CloudAccountDto:
        account.complete_discovery(cmd.tenant_id, cmd.discovered_asset_count, datetime.now(UTC))
        return _to_dto(account)

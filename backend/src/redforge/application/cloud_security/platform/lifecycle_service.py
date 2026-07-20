"""Thin lifecycle wrapper — register provider/account via foundation service only."""

from __future__ import annotations

from typing import Any, Protocol

from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountDTO,
    CloudProviderDTO,
    RegisterCloudAccountCommand,
    RegisterCloudProviderCommand,
)
from redforge.application.cloud_security.platform.dtos import (
    RegisterAccountLifecycleCommand,
    RegisterProviderLifecycleCommand,
)


class _FoundationLifecyclePort(Protocol):
    async def register_cloud_provider(
        self, command: RegisterCloudProviderCommand
    ) -> CloudProviderDTO: ...

    async def register_cloud_account(
        self, command: RegisterCloudAccountCommand
    ) -> CloudAccountDTO: ...


class CloudPlatformLifecycleService:
    """Delegates provider/account registration to CloudFoundationService."""

    def __init__(self, foundation: _FoundationLifecyclePort) -> None:
        self._foundation = foundation

    async def register_provider(
        self, command: RegisterProviderLifecycleCommand
    ) -> CloudProviderDTO:
        return await self._foundation.register_cloud_provider(
            RegisterCloudProviderCommand(
                organization_id=command.organization_id,
                provider_type=command.provider_type,
                display_name=command.display_name,
                polling_interval_seconds=command.polling_interval_seconds,
                region_filter=command.region_filter,
                service_filter=command.service_filter,
            )
        )

    async def register_account(
        self, command: RegisterAccountLifecycleCommand
    ) -> CloudAccountDTO:
        return await self._foundation.register_cloud_account(
            RegisterCloudAccountCommand(
                organization_id=command.organization_id,
                cloud_provider_id=command.cloud_provider_id,
                external_id=command.external_id,
                display_name=command.display_name,
                account_type=command.account_type,
                credential_reference_id=command.credential_reference_id,
                tags=command.tags,
            )
        )

    async def register_provider_raw(self, **kwargs: Any) -> CloudProviderDTO:
        return await self.register_provider(RegisterProviderLifecycleCommand(**kwargs))

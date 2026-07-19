"""Application service for M26 Cloud Security foundation administration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountDTO,
    CloudAccountPageDTO,
    CloudProviderDTO,
    DisableCloudProviderCommand,
    ListCloudAccountsQuery,
    ListCloudProvidersQuery,
    RegisterCloudAccountCommand,
    RegisterCloudProviderCommand,
    UpdateCloudProviderCommand,
)
from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.exceptions import (
    CloudAccountAlreadyExistsError,
    CloudProviderAlreadyExistsError,
    CloudProviderDisabledError,
    CloudProviderNotFoundError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudProviderId,
    CloudProviderType,
    CredentialRef,
    DiscoveryConfig,
    OrganizationId,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.repositories import (
        CloudAccountRepository,
        CloudProviderRepository,
    )

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    ProviderRepoFactory = Callable[[AsyncSession], CloudProviderRepository]
    AccountRepoFactory = Callable[[AsyncSession], CloudAccountRepository]


def _provider_dto(provider: CloudProvider) -> CloudProviderDTO:
    return CloudProviderDTO(
        provider_id=str(provider.id),
        organization_id=str(provider.organization_id),
        provider_type=provider.provider_type.value,
        display_name=provider.display_name,
        status=provider.status.value,
        polling_interval_seconds=provider.discovery_config.polling_interval_seconds,
        region_filter=list(provider.discovery_config.region_filter),
        service_filter=list(provider.discovery_config.service_filter),
        created_at=provider.created_at,
        updated_at=provider.updated_at,
        version=provider.version,
    )


def _account_dto(account: CloudAccount) -> CloudAccountDTO:
    return CloudAccountDTO(
        account_id=str(account.id),
        cloud_provider_id=str(account.cloud_provider_id),
        organization_id=str(account.organization_id),
        external_id=account.external_id,
        display_name=account.display_name,
        account_type=account.account_type.value,
        credential_reference_id=account.credential_ref.reference_id,
        sync_status=account.sync_state.status.value,
        tags=dict(account.tags),
        created_at=account.created_at,
        updated_at=account.updated_at,
        version=account.version,
    )


class CloudFoundationService:
    """Phase 1 application service: provider/account registration and listing."""

    def __init__(
        self,
        session_factory: SessionFactory,
        provider_repo_factory: ProviderRepoFactory,
        account_repo_factory: AccountRepoFactory,
    ) -> None:
        self._session_factory = session_factory
        self._provider_repo_factory = provider_repo_factory
        self._account_repo_factory = account_repo_factory

    async def register_cloud_provider(
        self, command: RegisterCloudProviderCommand
    ) -> CloudProviderDTO:
        try:
            provider_type = CloudProviderType(command.provider_type.upper())
        except ValueError as exc:
            raise InvalidCloudArgumentError("provider_type", "must be AWS|AZURE|GCP") from exc
        org = OrganizationId(command.organization_id)
        config = DiscoveryConfig(
            polling_interval_seconds=command.polling_interval_seconds,
            region_filter=command.region_filter,
            service_filter=command.service_filter,
        )
        async with self._session_factory() as session, session.begin():
            providers = self._provider_repo_factory(session)
            existing = await providers.get_by_org_and_type(org, provider_type)
            if existing is not None:
                raise CloudProviderAlreadyExistsError(str(org), provider_type.value)
            provider = CloudProvider.register(
                organization_id=org,
                provider_type=provider_type,
                display_name=command.display_name,
                discovery_config=config,
            )
            await providers.save(provider)
            provider.pop_events()
            return _provider_dto(provider)

    async def update_cloud_provider(self, command: UpdateCloudProviderCommand) -> CloudProviderDTO:
        org = OrganizationId(command.organization_id)
        provider_id = CloudProviderId.from_string(command.provider_id)
        async with self._session_factory() as session, session.begin():
            providers = self._provider_repo_factory(session)
            provider = await providers.get_by_id(provider_id, org)
            if provider is None:
                raise CloudProviderNotFoundError(command.provider_id)
            discovery = None
            if (
                command.polling_interval_seconds is not None
                or command.region_filter is not None
                or command.service_filter is not None
            ):
                discovery = DiscoveryConfig(
                    polling_interval_seconds=(
                        command.polling_interval_seconds
                        if command.polling_interval_seconds is not None
                        else provider.discovery_config.polling_interval_seconds
                    ),
                    region_filter=(
                        command.region_filter
                        if command.region_filter is not None
                        else provider.discovery_config.region_filter
                    ),
                    service_filter=(
                        command.service_filter
                        if command.service_filter is not None
                        else provider.discovery_config.service_filter
                    ),
                    tags_filter=provider.discovery_config.tags_filter,
                )
            provider.update(display_name=command.display_name, discovery_config=discovery)
            await providers.save(provider)
            provider.pop_events()
            return _provider_dto(provider)

    async def disable_cloud_provider(
        self, command: DisableCloudProviderCommand
    ) -> CloudProviderDTO:
        org = OrganizationId(command.organization_id)
        provider_id = CloudProviderId.from_string(command.provider_id)
        async with self._session_factory() as session, session.begin():
            providers = self._provider_repo_factory(session)
            provider = await providers.get_by_id(provider_id, org)
            if provider is None:
                raise CloudProviderNotFoundError(command.provider_id)
            provider.disable()
            await providers.save(provider)
            provider.pop_events()
            return _provider_dto(provider)

    async def register_cloud_account(self, command: RegisterCloudAccountCommand) -> CloudAccountDTO:
        org = OrganizationId(command.organization_id)
        provider_id = CloudProviderId.from_string(command.cloud_provider_id)
        try:
            account_type = CloudAccountType(command.account_type.upper())
        except ValueError as exc:
            raise InvalidCloudArgumentError(
                "account_type", "must be ROOT|MEMBER|STANDALONE"
            ) from exc
        async with self._session_factory() as session, session.begin():
            providers = self._provider_repo_factory(session)
            accounts = self._account_repo_factory(session)
            provider = await providers.get_by_id(provider_id, org)
            if provider is None:
                raise CloudProviderNotFoundError(command.cloud_provider_id)
            if provider.status.value == "DISABLED":
                raise CloudProviderDisabledError(command.cloud_provider_id)
            duplicate = await accounts.get_by_external_id(
                provider.provider_type, command.external_id.strip(), org
            )
            if duplicate is not None:
                raise CloudAccountAlreadyExistsError(str(provider_id), command.external_id)
            account = CloudAccount.register(
                cloud_provider_id=provider_id,
                organization_id=org,
                external_id=command.external_id,
                display_name=command.display_name,
                account_type=account_type,
                credential_ref=CredentialRef(reference_id=command.credential_reference_id),
                tags=command.tags,
            )
            await accounts.save(account)
            account.pop_events()
            return _account_dto(account)

    async def list_cloud_providers(self, query: ListCloudProvidersQuery) -> list[CloudProviderDTO]:
        org = OrganizationId(query.organization_id)
        async with self._session_factory() as session:
            providers = self._provider_repo_factory(session)
            items = await providers.list_by_organization(org)
            return [_provider_dto(item) for item in items]

    async def list_cloud_accounts(self, query: ListCloudAccountsQuery) -> CloudAccountPageDTO:
        org = OrganizationId(query.organization_id)
        async with self._session_factory() as session:
            accounts = self._account_repo_factory(session)
            if query.cloud_provider_id:
                provider_id = CloudProviderId.from_string(query.cloud_provider_id)
                items = await accounts.list_by_provider(provider_id, org)
                return CloudAccountPageDTO(
                    items=[_account_dto(item) for item in items],
                    page=1,
                    size=len(items),
                    total=len(items),
                )
            page = await accounts.list_by_organization(org, page=query.page, size=query.size)
            return CloudAccountPageDTO(
                items=[_account_dto(item) for item in page.items],
                page=page.page,
                size=page.size,
                total=page.total,
            )

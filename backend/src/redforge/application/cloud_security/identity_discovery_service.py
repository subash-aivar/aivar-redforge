"""Orchestrates Phase 3 cloud IAM identity discovery, upsert, and graph projection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.application.cloud_security.identity_dtos import (
    CloudIAMPrincipalDTO,
    CloudIAMPrincipalPageDTO,
    GetIAMPrincipalQuery,
    IdentityDiscoveryResultDTO,
    ListAttachedPoliciesQuery,
    ListIAMPrincipalsQuery,
    ListTrustRelationshipsQuery,
    PolicyAttachmentDTO,
    TriggerIdentityDiscoveryCommand,
    TrustRelationshipDTO,
)
from redforge.application.cloud_security.identity_normalization_service import (
    IdentityNormalizationService,
)
from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
from redforge.domain.cloud_security.exceptions import (
    CloudAccountNotFoundError,
    CloudIAMPrincipalNotFoundError,
    CloudProviderDisabledError,
    CloudProviderNotFoundError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudIAMPrincipalId,
    CloudProviderStatus,
    CloudProviderType,
    IAMPrincipalType,
    OrganizationId,
    PrivilegeLevel,
)
from redforge.infrastructure.cloud_security.adapters.aws import AWSCloudProviderAdapter
from redforge.infrastructure.cloud_security.adapters.azure import AzureCloudProviderAdapter
from redforge.infrastructure.cloud_security.adapters.gcp import GCPCloudProviderAdapter

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.application.cloud_security.discovery_client_factory import (
        DiscoveryClientFactory,
    )
    from redforge.application.cloud_security.identity_projection_service import (
        IdentityProjectionService,
    )
    from redforge.domain.cloud_security.ports import CloudProviderAdapter
    from redforge.domain.cloud_security.repositories import (
        CloudAccountRepository,
        CloudIAMPrincipalRepository,
        CloudProviderRepository,
    )

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    ProviderRepoFactory = Callable[[AsyncSession], CloudProviderRepository]
    AccountRepoFactory = Callable[[AsyncSession], CloudAccountRepository]
    PrincipalRepoFactory = Callable[[AsyncSession], CloudIAMPrincipalRepository]
    AdapterBuilder = Callable[[CloudProviderType, Any], CloudProviderAdapter]


def _default_adapter(provider_type: CloudProviderType, client: Any) -> CloudProviderAdapter:
    if provider_type is CloudProviderType.AWS:
        return AWSCloudProviderAdapter(client)
    if provider_type is CloudProviderType.AZURE:
        return AzureCloudProviderAdapter(client)
    if provider_type is CloudProviderType.GCP:
        return GCPCloudProviderAdapter(client)
    raise InvalidCloudArgumentError("provider_type", f"unsupported: {provider_type}")


def _policy_dto(policy: Any) -> PolicyAttachmentDTO:
    return PolicyAttachmentDTO(
        attachment_id=policy.attachment_id,
        policy_provider_id=policy.policy_provider_id,
        policy_name=policy.policy_name,
        attachment_type=policy.attachment_type.value,
        is_inline=policy.is_inline,
    )


def _trust_dto(trust: Any) -> TrustRelationshipDTO:
    return TrustRelationshipDTO(
        trust_id=trust.trust_id,
        trusted_principal_provider_id=trust.trusted_principal_provider_id,
        trust_type=trust.trust_type,
        is_cross_account=trust.is_cross_account,
        conditions=[[k, v] for k, v in trust.conditions],
    )


def _principal_dto(
    principal: CloudIAMPrincipal, *, include_detail: bool = False
) -> CloudIAMPrincipalDTO:
    return CloudIAMPrincipalDTO(
        principal_id=str(principal.id),
        cloud_account_id=str(principal.cloud_account_id),
        organization_id=str(principal.organization_id),
        principal_type=principal.principal_type.value,
        provider_id=principal.provider_id,
        display_name=principal.display_name,
        privilege_level=principal.privilege_level.value,
        is_federated=principal.is_federated,
        is_human=principal.is_human,
        is_disabled=principal.is_disabled,
        is_deleted=principal.is_deleted,
        last_activity_at=principal.last_activity_at,
        last_seen_at=principal.last_seen_at,
        first_seen_at=principal.first_seen_at,
        created_at=principal.created_at,
        updated_at=principal.updated_at,
        version=principal.version,
        attached_policies=[_policy_dto(p) for p in principal.attached_policies]
        if include_detail
        else [],
        trust_relationships=[_trust_dto(t) for t in principal.trust_relationships]
        if include_detail
        else [],
    )


class IdentityDiscoveryService:
    """Phase 3 application service: discover, upsert, soft-delete, project, query IAM."""

    def __init__(
        self,
        session_factory: SessionFactory,
        provider_repo_factory: ProviderRepoFactory,
        account_repo_factory: AccountRepoFactory,
        principal_repo_factory: PrincipalRepoFactory,
        client_factory: DiscoveryClientFactory,
        identity_projection: IdentityProjectionService | None = None,
        normalization_service: IdentityNormalizationService | None = None,
        adapter_builder: AdapterBuilder | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._provider_repo_factory = provider_repo_factory
        self._account_repo_factory = account_repo_factory
        self._principal_repo_factory = principal_repo_factory
        self._client_factory = client_factory
        self._identity_projection = identity_projection
        self._normalization = normalization_service or IdentityNormalizationService()
        self._adapter_builder = adapter_builder or _default_adapter

    async def discover_account(
        self, command: TriggerIdentityDiscoveryCommand
    ) -> IdentityDiscoveryResultDTO:
        org = OrganizationId(command.organization_id)
        account_id = CloudAccountId.from_string(command.cloud_account_id)

        async with self._session_factory() as session, session.begin():
            providers = self._provider_repo_factory(session)
            accounts = self._account_repo_factory(session)
            account = await accounts.get_by_id(account_id, org)
            if account is None:
                raise CloudAccountNotFoundError(command.cloud_account_id)
            provider = await providers.get_by_id(account.cloud_provider_id, org)
            if provider is None:
                raise CloudProviderNotFoundError(str(account.cloud_provider_id))
            if provider.status is CloudProviderStatus.DISABLED:
                raise CloudProviderDisabledError(str(provider.id))
            account.mark_sync_started()
            await accounts.save(account)
            account.pop_events()
            provider_type = provider.provider_type
            credential_ref = account.credential_ref

        discovered = updated = resurrected = deleted = projected = 0
        try:
            async with self._session_factory() as session, session.begin():
                providers = self._provider_repo_factory(session)
                accounts = self._account_repo_factory(session)
                principals = self._principal_repo_factory(session)
                account = await accounts.get_by_id(account_id, org)
                if account is None:
                    raise CloudAccountNotFoundError(command.cloud_account_id)
                provider = await providers.get_by_id(account.cloud_provider_id, org)
                if provider is None:
                    raise CloudProviderNotFoundError(str(account.cloud_provider_id))

                client = self._client_factory.create(provider_type, credential_ref)
                adapter = self._adapter_builder(provider_type, client)

                seen_provider_ids: set[str] = set()
                upserted: list[CloudIAMPrincipal] = []

                async for raw in adapter.list_iam_principals(account):
                    draft = self._normalization.normalize(raw)
                    seen_provider_ids.add(draft.provider_id)
                    existing = await principals.get_by_provider_id(
                        account.id, draft.provider_id, org
                    )
                    if existing is None:
                        principal = CloudIAMPrincipal.discover(
                            cloud_account_id=account.id,
                            organization_id=org,
                            principal_type=draft.principal_type,
                            provider_id=draft.provider_id,
                            display_name=draft.display_name,
                            attached_policies=draft.attached_policies,
                            trust_relationships=draft.trust_relationships,
                            is_federated=draft.is_federated,
                            is_human=draft.is_human,
                            last_activity_at=draft.last_activity_at,
                            privilege_level=PrivilegeLevel.NONE,
                        )
                        discovered += 1
                    elif existing.is_deleted:
                        existing.resurrect_from_discovery(
                            display_name=draft.display_name,
                            attached_policies=draft.attached_policies,
                            trust_relationships=draft.trust_relationships,
                            is_federated=draft.is_federated,
                            is_human=draft.is_human,
                            last_activity_at=draft.last_activity_at,
                        )
                        principal = existing
                        resurrected += 1
                    else:
                        existing.apply_discovery(
                            display_name=draft.display_name,
                            attached_policies=draft.attached_policies,
                            trust_relationships=draft.trust_relationships,
                            is_federated=draft.is_federated,
                            is_human=draft.is_human,
                            last_activity_at=draft.last_activity_at,
                        )
                        principal = existing
                        updated += 1
                    await principals.save(principal)
                    principal.pop_events()
                    upserted.append(principal)

                deleted_principals = await principals.mark_deleted(
                    seen_provider_ids, account.id, org
                )
                deleted = len(deleted_principals)
                for deleted_principal in deleted_principals:
                    deleted_principal.pop_events()

                if self._identity_projection is not None:
                    for principal in upserted:
                        if principal.is_deleted:
                            continue
                        await self._identity_projection.project(principal=principal)
                        projected += 1

                account.mark_sync_completed()
                await accounts.save(account)
                account.pop_events()
                return IdentityDiscoveryResultDTO(
                    cloud_account_id=str(account.id),
                    organization_id=str(org),
                    sync_status=account.sync_state.status.value,
                    discovered_count=discovered,
                    updated_count=updated,
                    resurrected_count=resurrected,
                    deleted_count=deleted,
                    projected_count=projected,
                )
        except Exception as exc:
            async with self._session_factory() as session, session.begin():
                accounts = self._account_repo_factory(session)
                account = await accounts.get_by_id(account_id, org)
                if account is not None:
                    account.mark_sync_failed(str(exc)[:512])
                    await accounts.save(account)
                    account.pop_events()
            raise

    async def list_principals(self, query: ListIAMPrincipalsQuery) -> CloudIAMPrincipalPageDTO:
        org = OrganizationId(query.organization_id)
        principal_type = None
        if query.principal_type:
            try:
                principal_type = IAMPrincipalType(query.principal_type.upper())
            except ValueError as exc:
                raise InvalidCloudArgumentError(
                    "principal_type", f"unknown type: {query.principal_type}"
                ) from exc
        account_id = (
            CloudAccountId.from_string(query.cloud_account_id) if query.cloud_account_id else None
        )
        async with self._session_factory() as session:
            principals = self._principal_repo_factory(session)
            page = await principals.list_by_organization(
                org,
                page=query.page,
                size=query.size,
                include_deleted=query.include_deleted,
                cloud_account_id=account_id,
                principal_type=principal_type,
            )
            return CloudIAMPrincipalPageDTO(
                items=[_principal_dto(item) for item in page.items],
                page=page.page,
                size=page.size,
                total=page.total,
            )

    async def get_principal(self, query: GetIAMPrincipalQuery) -> CloudIAMPrincipalDTO:
        org = OrganizationId(query.organization_id)
        principal_id = CloudIAMPrincipalId.from_string(query.principal_id)
        async with self._session_factory() as session:
            principals = self._principal_repo_factory(session)
            principal = await principals.get_by_id(principal_id, org)
            if principal is None:
                raise CloudIAMPrincipalNotFoundError(query.principal_id)
            return _principal_dto(principal, include_detail=True)

    async def list_attached_policies(
        self, query: ListAttachedPoliciesQuery
    ) -> list[PolicyAttachmentDTO]:
        org = OrganizationId(query.organization_id)
        principal_id = CloudIAMPrincipalId.from_string(query.principal_id)
        async with self._session_factory() as session:
            principals = self._principal_repo_factory(session)
            principal = await principals.get_by_id(principal_id, org)
            if principal is None:
                raise CloudIAMPrincipalNotFoundError(query.principal_id)
            return [_policy_dto(p) for p in principal.attached_policies]

    async def list_trust_relationships(
        self, query: ListTrustRelationshipsQuery
    ) -> list[TrustRelationshipDTO]:
        org = OrganizationId(query.organization_id)
        principal_id = CloudIAMPrincipalId.from_string(query.principal_id)
        async with self._session_factory() as session:
            principals = self._principal_repo_factory(session)
            principal = await principals.get_by_id(principal_id, org)
            if principal is None:
                raise CloudIAMPrincipalNotFoundError(query.principal_id)
            return [_trust_dto(t) for t in principal.trust_relationships]

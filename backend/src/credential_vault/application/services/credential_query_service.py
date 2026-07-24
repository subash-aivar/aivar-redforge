"""Credential and version query service (CQRS read side)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.application._validation import (
    validate_limit,
    validate_offset,
    validate_uuid,
)
from credential_vault.application.dtos.credential_dtos import CredentialDTO, VersionDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied, CredentialIsDeleted
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    TenantId,
    VersionId,
)
from credential_vault.domain.value_objects.states import CredentialState, VersionState

if TYPE_CHECKING:
    from credential_vault.application.queries.credential_queries import (
        GetCredentialQuery,
        GetVersionQuery,
        ListCredentialsQuery,
        ListVersionsQuery,
    )
    from credential_vault.domain.repositories.i_credential_repository import (
        ICredentialRepository,
    )
    from credential_vault.domain.repositories.i_credential_version_repository import (
        ICredentialVersionRepository,
    )


class CredentialQueryService:
    """Read-side queries for credentials and versions. No UoW, mutations, or events."""

    def __init__(
        self,
        credential_repo: ICredentialRepository,
        version_repo: ICredentialVersionRepository,
        permission_port: IPermissionPort,
    ) -> None:
        self._credential_repo = credential_repo
        self._version_repo = version_repo
        self._permission_port = permission_port

    async def _require_read(
        self,
        principal_id: PrincipalId,
        credential_id: CredentialId,
        tenant_id: TenantId,
    ) -> None:
        allowed = await self._permission_port.has_permission(
            principal_id,
            credential_id,
            IPermissionPort.PERMISSION_READ,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                principal_id,
                IPermissionPort.PERMISSION_READ,
                credential_id,
            )

    def _parse_credential_states(self, states: list[str] | None) -> list[CredentialState] | None:
        if states is None:
            return None
        parsed: list[CredentialState] = []
        for value in states:
            try:
                parsed.append(CredentialState(value))
            except ValueError as exc:
                raise ApplicationValidationError(
                    "states", f"invalid CredentialState: {value}"
                ) from exc
        return parsed

    def _parse_version_states(self, states: list[str] | None) -> list[VersionState] | None:
        if states is None:
            return None
        parsed: list[VersionState] = []
        for value in states:
            try:
                parsed.append(VersionState(value))
            except ValueError as exc:
                raise ApplicationValidationError(
                    "states", f"invalid VersionState: {value}"
                ) from exc
        return parsed

    async def get_credential(self, qry: GetCredentialQuery) -> CredentialDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.credential_id, "credential_id")
        validate_uuid(qry.principal_id, "principal_id")

        credential_id = CredentialId(qry.credential_id)
        tenant_id = qry.tenant_id
        principal = PrincipalId(qry.principal_id.value.to_uuid())

        await self._require_read(principal, credential_id, tenant_id)
        credential = await self._credential_repo.get_by_id(credential_id, tenant_id)
        if credential.state == CredentialState.DELETED:
            raise CredentialIsDeleted(credential_id)
        return CredentialDTO.from_aggregate(credential)

    async def list_credentials(self, qry: ListCredentialsQuery) -> list[CredentialDTO]:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.principal_id, "principal_id")
        validated_limit = validate_limit(qry.limit)
        validate_offset(qry.offset)
        parsed_states = self._parse_credential_states(qry.states)

        credentials = await self._credential_repo.list_by_tenant(
            qry.tenant_id,
            parsed_states,
            validated_limit,
            qry.offset,
        )
        return [CredentialDTO.from_aggregate(credential) for credential in credentials]

    async def get_version(self, qry: GetVersionQuery) -> VersionDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.credential_id, "credential_id")
        validate_uuid(qry.version_id, "version_id")
        validate_uuid(qry.principal_id, "principal_id")

        credential_id = CredentialId(qry.credential_id)
        tenant_id = qry.tenant_id
        principal = PrincipalId(qry.principal_id.value.to_uuid())

        await self._require_read(principal, credential_id, tenant_id)
        version = await self._version_repo.get_by_id(VersionId(qry.version_id), tenant_id)
        return VersionDTO.from_entity(version)

    async def list_versions(self, qry: ListVersionsQuery) -> list[VersionDTO]:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.credential_id, "credential_id")
        validate_uuid(qry.principal_id, "principal_id")

        credential_id = CredentialId(qry.credential_id)
        tenant_id = qry.tenant_id
        principal = PrincipalId(qry.principal_id.value.to_uuid())
        parsed_states = self._parse_version_states(qry.states)

        await self._require_read(principal, credential_id, tenant_id)
        versions = await self._version_repo.list_by_credential(
            credential_id,
            tenant_id,
            parsed_states,
        )
        return [VersionDTO.from_entity(version) for version in versions]

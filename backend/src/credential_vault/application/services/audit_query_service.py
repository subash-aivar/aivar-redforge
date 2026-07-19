"""Audit log query service (CQRS read side)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.application._validation import (
    validate_limit,
    validate_offset,
    validate_uuid,
)
from credential_vault.application.dtos.audit_dtos import AuditEntryDTO
from credential_vault.application.exceptions import ApplicationValidationError
from credential_vault.domain.exceptions.domain_exceptions import AccessDenied
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.value_objects.audit_types import AuditOperation
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    PrincipalId,
    TenantId,
)

if TYPE_CHECKING:
    from credential_vault.application.queries.audit_queries import ListAuditEntriesQuery
    from credential_vault.domain.repositories.i_audit_log_repository import (
        IAuditLogRepository,
    )
    from credential_vault.domain.repositories.i_credential_repository import (
        ICredentialRepository,
    )


class AuditQueryService:
    """Read-side queries for credential audit entries. No UoW, mutations, or events."""

    def __init__(
        self,
        audit_log_repo: IAuditLogRepository,
        credential_repo: ICredentialRepository,
        permission_port: IPermissionPort,
    ) -> None:
        self._audit_log_repo = audit_log_repo
        self._credential_repo = credential_repo
        self._permission_port = permission_port

    def _parse_operations(self, operations: list[str] | None) -> list[AuditOperation] | None:
        if operations is None:
            return None
        parsed: list[AuditOperation] = []
        for value in operations:
            try:
                parsed.append(AuditOperation(value))
            except ValueError as exc:
                raise ApplicationValidationError(
                    "operations", f"invalid AuditOperation: {value}"
                ) from exc
        return parsed

    async def list_audit_entries(self, qry: ListAuditEntriesQuery) -> list[AuditEntryDTO]:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.credential_id, "credential_id")
        validate_uuid(qry.principal_id, "principal_id")
        validated_limit = validate_limit(qry.limit)
        validate_offset(qry.offset)
        parsed_operations = self._parse_operations(qry.operations)

        credential_id = CredentialId(qry.credential_id)
        tenant_id = TenantId(qry.tenant_id)
        principal = PrincipalId(qry.principal_id)

        allowed = await self._permission_port.has_permission(
            principal,
            credential_id,
            IPermissionPort.PERMISSION_READ,
            tenant_id,
        )
        if not allowed:
            raise AccessDenied(
                principal,
                IPermissionPort.PERMISSION_READ,
                credential_id,
            )

        audit_log = await self._audit_log_repo.get_by_credential(credential_id, tenant_id)
        entries = await self._audit_log_repo.list_entries(
            audit_log.audit_log_id,
            tenant_id,
            qry.since,
            parsed_operations,
            validated_limit,
            qry.offset,
        )
        return [AuditEntryDTO.from_entity(entry) for entry in entries]

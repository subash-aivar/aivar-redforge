"""IPermissionPort — queries platform permissions subsystem."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
    )


class IPermissionPort(ABC):
    """
    Queries the permissions subsystem (Platform bounded context).
    Returns boolean — does not raise AccessDenied itself.
    """

    PERMISSION_READ = "READ"
    PERMISSION_WRITE = "WRITE"
    PERMISSION_ROTATE = "ROTATE"
    PERMISSION_REVOKE = "REVOKE"
    PERMISSION_EMERGENCY_REVOKE = "EMERGENCY_REVOKE"
    PERMISSION_DELETE = "DELETE"
    PERMISSION_MANAGE_POLICY = "MANAGE_POLICY"
    PERMISSION_BREAK_GLASS = "BREAK_GLASS"
    PERMISSION_ADMIN = "ADMIN"

    @abstractmethod
    async def has_permission(
        self,
        principal_id: PrincipalId,
        credential_id: CredentialId,
        permission: str,
        tenant_id: TenantId,
    ) -> bool: ...

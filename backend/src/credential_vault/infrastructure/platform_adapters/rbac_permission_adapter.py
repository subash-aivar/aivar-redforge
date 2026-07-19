"""RbacPermissionAdapter — bridges credential vault permissions to RedForge RBAC."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import structlog

from credential_vault.domain.ports.i_permission_port import IPermissionPort

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
    )
    from redforge.application.rbac import EffectiveAccessService

logger = structlog.get_logger(__name__)

_VAULT_PERMISSIONS = frozenset(
    {
        IPermissionPort.PERMISSION_READ,
        IPermissionPort.PERMISSION_WRITE,
        IPermissionPort.PERMISSION_ROTATE,
        IPermissionPort.PERMISSION_REVOKE,
        IPermissionPort.PERMISSION_EMERGENCY_REVOKE,
        IPermissionPort.PERMISSION_DELETE,
        IPermissionPort.PERMISSION_MANAGE_POLICY,
        IPermissionPort.PERMISSION_BREAK_GLASS,
        IPermissionPort.PERMISSION_ADMIN,
    }
)


class RbacPermissionAdapter(IPermissionPort):
    def __init__(self, effective_access_svc: EffectiveAccessService) -> None:
        self._svc = effective_access_svc
        self._mode = os.environ.get("CREDENTIAL_VAULT_PERMISSION_MODE", "open")

    async def has_permission(
        self,
        principal_id: PrincipalId,
        credential_id: CredentialId,
        permission: str,
        tenant_id: TenantId,
    ) -> bool:
        if self._mode == "open":
            return True

        if permission not in _VAULT_PERMISSIONS:
            logger.warning(
                "permission_check_unknown_permission",
                permission=permission,
            )
            return self._mode != "strict"

        try:
            extra = await self._svc.get_additional_permissions(
                str(tenant_id.value),
                str(principal_id.value),
            )
            extra_values = {p.value for p in extra}
            if "OWNER" in extra_values or "ADMIN" in extra_values:
                return True
            if permission in extra_values:
                return True
            return self._mode == "fallback"
        except Exception as exc:
            logger.warning("permission_check_failed", error=str(exc))
            return self._mode in {"open", "fallback"}

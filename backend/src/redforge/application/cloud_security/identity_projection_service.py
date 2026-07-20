"""Application wrapper for CloudIAMPrincipal → security graph projection."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
    from redforge.infrastructure.cloud_security.acl.iam_graph_acl import CloudIAMToGraphACL


class IdentityProjectionService:
    """Projects non-deleted CloudIAMPrincipals into the security graph."""

    def __init__(self, acl: CloudIAMToGraphACL) -> None:
        self._acl = acl

    async def project(self, *, principal: CloudIAMPrincipal) -> None:
        await self._acl.project_principal(principal=principal)

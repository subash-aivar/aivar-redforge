"""CloudIAMPrincipal → Security Graph projection ACL (best-effort)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

logger = logging.getLogger(__name__)


class CloudIAMToGraphACL:
    """Projects CloudIAMPrincipal aggregates into the M4 security graph.

    Uses a separate SessionUnitOfWork so projection failures never roll back
    the canonical IAM write (mirrors TenantAssetService._project_best_effort).
    """

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def project_principal(self, *, principal: CloudIAMPrincipal) -> None:
        if principal.is_deleted:
            return
        organization_id = str(principal.organization_id)
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                from redforge.application.security_graph import projector as sg_projector
                from redforge.infrastructure.database.repositories import (
                    security_graph_repository as sg_repo,
                )

                repo = sg_repo.SecurityGraphRepository(graph_uow.session)
                projector = sg_projector.SecurityGraphProjector(repo)
                await projector.project_cloud_iam_principal(
                    organization_id=organization_id,
                    principal_id=str(principal.id),
                    principal_type=principal.principal_type.value,
                    display_name=principal.display_name,
                    provider_id=principal.provider_id,
                )
                for policy in principal.attached_policies:
                    await projector.project_iam_has_policy(
                        organization_id=organization_id,
                        principal_id=str(principal.id),
                        policy_provider_id=policy.policy_provider_id,
                        policy_name=policy.policy_name,
                    )
                for trust in principal.trust_relationships:
                    await projector.project_iam_trust(
                        organization_id=organization_id,
                        principal_id=str(principal.id),
                        trusted_provider_id=trust.trusted_principal_provider_id,
                    )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: IAM principal projection failed for principal_id=%s",
                principal.id,
                exc_info=True,
            )

"""CSPMFinding → Security Graph projection ACL (best-effort)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.cspm.finding import CSPMFinding
    from redforge.domain.cloud_security.cspm.policy import CSPMPolicy

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

logger = logging.getLogger(__name__)


class CSPMFindingToGraphACL:
    """Projects CSPM findings/controls and AFFECTS/VIOLATES/EVALUATED_BY edges."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def project_finding(
        self, *, finding: CSPMFinding, policy: CSPMPolicy | None = None
    ) -> None:
        organization_id = str(finding.organization_id)
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                from redforge.application.security_graph import projector as sg_projector
                from redforge.infrastructure.database.repositories import (
                    security_graph_repository as sg_repo,
                )

                repo = sg_repo.SecurityGraphRepository(graph_uow.session)
                projector = sg_projector.SecurityGraphProjector(repo)
                await projector.project_cspm_finding(
                    organization_id=organization_id,
                    finding_id=str(finding.id),
                    title=finding.title,
                    severity=finding.severity.value,
                    status=finding.status.value,
                    policy_id=str(finding.policy_id),
                    rule_id=str(finding.rule_id),
                )
                await projector.project_cspm_affects(
                    organization_id=organization_id,
                    finding_id=str(finding.id),
                    cloud_asset_id=str(finding.cloud_asset_id),
                )
                control_ids: list[str] = []
                if policy is not None:
                    for ref in policy.compliance_mapping:
                        control_key = f"{ref.framework_key}:{ref.requirement_ref}"
                        control_ids.append(control_key)
                        await projector.project_cspm_control(
                            organization_id=organization_id,
                            control_id=control_key,
                            framework_key=ref.framework_key,
                            requirement_ref=ref.requirement_ref,
                            label=f"{ref.framework_key} {ref.requirement_ref}",
                        )
                else:
                    for ref in finding.compliance_mapping:
                        control_key = f"{ref.framework_key}:{ref.requirement_ref}"
                        control_ids.append(control_key)
                        await projector.project_cspm_control(
                            organization_id=organization_id,
                            control_id=control_key,
                            framework_key=ref.framework_key,
                            requirement_ref=ref.requirement_ref,
                            label=f"{ref.framework_key} {ref.requirement_ref}",
                        )
                for control_id in control_ids:
                    await projector.project_cspm_violates(
                        organization_id=organization_id,
                        finding_id=str(finding.id),
                        control_id=control_id,
                    )
                    await projector.project_cspm_evaluated_by(
                        organization_id=organization_id,
                        finding_id=str(finding.id),
                        control_id=control_id,
                    )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: CSPM finding projection failed for finding_id=%s",
                finding.id,
                exc_info=True,
            )

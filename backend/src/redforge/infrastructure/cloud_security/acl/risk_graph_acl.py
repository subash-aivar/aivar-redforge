"""Cloud risk → Security Graph projection ACL (best-effort, no traversal)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.risk.factor import CloudRiskExposure, CloudRiskFactor
    from redforge.domain.cloud_security.risk.score import CloudRiskScore

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

logger = logging.getLogger(__name__)


class RiskGraphACL:
    """Projects RISK / RISK_FACTOR / RISK_EXPOSURE nodes and HAS_* edges."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def project_risk(self, *, score: CloudRiskScore) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                org = str(score.organization_id)
                await projector.project_cloud_risk(
                    organization_id=org,
                    risk_id=str(score.id),
                    cloud_asset_id=str(score.cloud_asset_id),
                    overall_score=score.overall_score,
                    state=score.state.value,
                )
                await projector.project_cloud_risk_has_risk(
                    organization_id=org,
                    cloud_asset_id=str(score.cloud_asset_id),
                    risk_id=str(score.id),
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: risk score projection failed for %s",
                score.id,
                exc_info=True,
            )

    async def project_factor(self, *, factor: CloudRiskFactor, risk_id: str) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                org = str(factor.organization_id)
                await projector.project_cloud_risk_factor(
                    organization_id=org,
                    factor_id=str(factor.id),
                    title=factor.title,
                    score=factor.score,
                    category=factor.category.value,
                )
                await projector.project_cloud_risk_has_factor(
                    organization_id=org,
                    risk_id=risk_id,
                    factor_id=str(factor.id),
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: risk factor projection failed for %s",
                factor.id,
                exc_info=True,
            )

    async def project_exposure(self, *, exposure: CloudRiskExposure, risk_id: str) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                org = str(exposure.organization_id)
                await projector.project_cloud_risk_exposure(
                    organization_id=org,
                    exposure_id=str(exposure.id),
                    exposure_score=exposure.exposure_score,
                    public_accessibility=exposure.public_accessibility,
                )
                await projector.project_cloud_risk_has_exposure(
                    organization_id=org,
                    risk_id=risk_id,
                    exposure_id=str(exposure.id),
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: risk exposure projection failed for %s",
                exposure.id,
                exc_info=True,
            )

    def _projector(self, session: Any) -> Any:
        from redforge.application.security_graph import projector as sg_projector
        from redforge.infrastructure.database.repositories import (
            security_graph_repository as sg_repo,
        )

        repo = sg_repo.SecurityGraphRepository(session)
        return sg_projector.SecurityGraphProjector(repo)

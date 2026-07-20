"""Application-level risk graph projection wrapper."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.domain.cloud_security.risk.factor import CloudRiskExposure, CloudRiskFactor
    from redforge.domain.cloud_security.risk.score import CloudRiskScore


class RiskGraphProjector(Protocol):
    async def project_risk(self, *, score: CloudRiskScore) -> None: ...

    async def project_factor(self, *, factor: CloudRiskFactor, risk_id: str) -> None: ...

    async def project_exposure(
        self, *, exposure: CloudRiskExposure, risk_id: str
    ) -> None: ...


class RiskProjectionService:
    def __init__(self, graph_acl: RiskGraphProjector | None = None) -> None:
        self._acl = graph_acl

    async def project(
        self,
        *,
        score: CloudRiskScore,
        factors: list[CloudRiskFactor] | None = None,
        exposure: CloudRiskExposure | None = None,
    ) -> None:
        if self._acl is None:
            return
        await self._acl.project_risk(score=score)
        risk_id = str(score.id)
        for factor in factors or []:
            await self._acl.project_factor(factor=factor, risk_id=risk_id)
        if exposure is not None:
            await self._acl.project_exposure(exposure=exposure, risk_id=risk_id)

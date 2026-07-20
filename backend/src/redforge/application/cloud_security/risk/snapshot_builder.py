"""Build RiskSignalSnapshot from existing domain repos (read-only signals)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from redforge.domain.cloud_security.risk.engine import RiskSignalSnapshot
from redforge.infrastructure.cloud_security.acl.exposure_acl import ExposureSignalACL
from redforge.infrastructure.cloud_security.acl.threat_intel_acl import ThreatIntelRiskACL

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from uuid import UUID

    from redforge.domain.cloud_security.cloud_asset import CloudAsset
    from redforge.domain.cloud_security.value_objects import OrganizationId


class FindingSeverityLoader(Protocol):
    async def __call__(
        self, asset: CloudAsset, organization_id: OrganizationId
    ) -> tuple[str, ...]: ...


class PrivilegeLoader(Protocol):
    async def __call__(
        self, asset: CloudAsset, organization_id: OrganizationId
    ) -> str: ...


class K8sScoreLoader(Protocol):
    async def __call__(
        self, asset: CloudAsset, organization_id: OrganizationId
    ) -> float | None: ...


class RuntimeSeverityLoader(Protocol):
    async def __call__(
        self, asset: CloudAsset, organization_id: OrganizationId
    ) -> tuple[str, ...]: ...


class RiskEvidenceCollector:
    """Collects provider-agnostic risk signals without persisting duplicates."""

    def __init__(
        self,
        *,
        finding_severities: FindingSeverityLoader | None = None,
        privilege_level: PrivilegeLoader | None = None,
        k8s_score: K8sScoreLoader | None = None,
        runtime_severities: RuntimeSeverityLoader | None = None,
        threat_intel: ThreatIntelRiskACL | None = None,
        exposure_acl: ExposureSignalACL | None = None,
        compliance_gap_loader: Callable[[CloudAsset], Awaitable[float]] | None = None,
    ) -> None:
        self._findings = finding_severities
        self._privilege = privilege_level
        self._k8s = k8s_score
        self._runtime = runtime_severities
        self._threat_intel = threat_intel or ThreatIntelRiskACL()
        self._exposure = exposure_acl or ExposureSignalACL()
        self._compliance_gap = compliance_gap_loader

    async def collect(self, asset: CloudAsset) -> RiskSignalSnapshot:
        org = asset.organization_id
        findings: tuple[str, ...] = ()
        if self._findings is not None:
            findings = await self._findings(asset, org)

        privilege = "NONE"
        if self._privilege is not None:
            privilege = await self._privilege(asset, org)

        k8s: float | None = None
        if self._k8s is not None:
            k8s = await self._k8s(asset, org)

        runtime: tuple[str, ...] = ()
        if self._runtime is not None:
            runtime = await self._runtime(asset, org)

        exposure = self._exposure.from_asset(asset)
        gap = 0.0
        if self._compliance_gap is not None:
            gap = float(await self._compliance_gap(asset))
        elif findings:
            # Lightweight proxy: more open findings → higher compliance gap
            gap = min(1.0, len(findings) / 10.0)

        ti = await self._threat_intel.threat_intel_score_for_asset(asset)
        criticality = (asset.tags or {}).get("criticality", "MEDIUM")
        return RiskSignalSnapshot(
            open_finding_severities=findings,
            privilege_level=privilege.upper(),
            network_exposure=str(exposure["network_exposure"]),
            encryption_at_rest=bool(exposure["encryption_at_rest"]),
            public_accessibility=bool(exposure["public_accessibility"]),
            compliance_gap_ratio=gap,
            k8s_security_score=k8s,
            runtime_event_severities=runtime,
            business_criticality=str(criticality).upper(),
            threat_intel_score=float(ti),
            lateral_movement_potential="UNKNOWN",
            provider_type="*",
            asset_type=str(
                asset.asset_type.value
                if hasattr(asset.asset_type, "value")
                else asset.asset_type
            ),
            tags=tuple(sorted((asset.tags or {}).items())),
        )


class RiskSnapshotBuilder:
    """Facade over RiskEvidenceCollector for pipeline use."""

    def __init__(self, collector: RiskEvidenceCollector | None = None) -> None:
        self._collector = collector or RiskEvidenceCollector()

    async def build(self, asset: CloudAsset) -> RiskSignalSnapshot:
        return await self._collector.collect(asset)

    async def build_for_assets(
        self, assets: list[CloudAsset]
    ) -> dict[UUID, RiskSignalSnapshot]:
        out: dict[UUID, RiskSignalSnapshot] = {}
        for asset in assets:
            out[asset.id.value] = await self.build(asset)
        return out

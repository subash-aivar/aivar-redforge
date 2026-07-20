"""Drift detection foundation — baseline store/compare by config_hash (no workers)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

from redforge.domain.cloud_security.cspm.entities import CSPMDriftBaseline
from redforge.domain.cloud_security.cspm.value_objects import DriftKind, ResourceSnapshot
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

if TYPE_CHECKING:
    from redforge.domain.cloud_security.cspm.repositories import CSPMDriftBaselineRepository


@dataclass(frozen=True, slots=True)
class DriftDiagnostic:
    cloud_asset_id: str
    drift_kind: str
    drifted: bool
    previous_hash: str | None
    current_hash: str
    message: str


class DriftDetectionService:
    """Store and compare configuration baselines for CSPM assets."""

    def __init__(self, baseline_repo: CSPMDriftBaselineRepository) -> None:
        self._repo = baseline_repo

    async def ensure_baseline(
        self,
        *,
        snapshot: ResourceSnapshot,
        drift_kind: DriftKind = DriftKind.CONFIGURATION,
    ) -> tuple[CSPMDriftBaseline, DriftDiagnostic]:
        org = OrganizationId(snapshot.organization_id)
        asset_id = CloudAssetId.from_string(snapshot.cloud_asset_id)
        existing = await self._repo.get_by_asset(org, asset_id, drift_kind.value)
        if existing is None:
            baseline = CSPMDriftBaseline.create(
                organization_id=snapshot.organization_id,
                cloud_asset_id=UUID(snapshot.cloud_asset_id),
                drift_kind=drift_kind.value,
                baseline_hash=snapshot.config_hash,
                baseline_snapshot=snapshot.to_dict(),
            )
            await self._repo.save(baseline)
            diagnostic = DriftDiagnostic(
                cloud_asset_id=snapshot.cloud_asset_id,
                drift_kind=drift_kind.value,
                drifted=False,
                previous_hash=None,
                current_hash=snapshot.config_hash,
                message="baseline_created",
            )
            return baseline, diagnostic

        drifted = existing.baseline_hash != snapshot.config_hash
        diagnostic = DriftDiagnostic(
            cloud_asset_id=snapshot.cloud_asset_id,
            drift_kind=drift_kind.value,
            drifted=drifted,
            previous_hash=existing.baseline_hash,
            current_hash=snapshot.config_hash,
            message="config_drift_detected" if drifted else "baseline_unchanged",
        )
        return existing, diagnostic

    async def update_baseline(
        self,
        *,
        snapshot: ResourceSnapshot,
        drift_kind: DriftKind = DriftKind.CONFIGURATION,
    ) -> CSPMDriftBaseline:
        org = OrganizationId(snapshot.organization_id)
        asset_id = CloudAssetId.from_string(snapshot.cloud_asset_id)
        existing = await self._repo.get_by_asset(org, asset_id, drift_kind.value)
        if existing is None:
            baseline = CSPMDriftBaseline.create(
                organization_id=snapshot.organization_id,
                cloud_asset_id=UUID(snapshot.cloud_asset_id),
                drift_kind=drift_kind.value,
                baseline_hash=snapshot.config_hash,
                baseline_snapshot=snapshot.to_dict(),
            )
            await self._repo.save(baseline)
            return baseline
        existing.update_baseline(
            baseline_hash=snapshot.config_hash,
            baseline_snapshot=snapshot.to_dict(),
        )
        await self._repo.save(existing)
        return existing

    def diagnostics_to_dict(self, items: list[DriftDiagnostic]) -> dict[str, Any]:
        return {
            "drift": [
                {
                    "cloud_asset_id": d.cloud_asset_id,
                    "drift_kind": d.drift_kind,
                    "drifted": d.drifted,
                    "previous_hash": d.previous_hash,
                    "current_hash": d.current_hash,
                    "message": d.message,
                }
                for d in items
            ]
        }

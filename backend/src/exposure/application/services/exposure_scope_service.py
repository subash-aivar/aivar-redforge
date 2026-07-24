"""ExposureScopeService — serves M30 IExposureScopeQueryPort (Phase 4/5)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from exposure.application._auth import require_at_least
from exposure.domain.value_objects.enums import ExposureRole
from exposure.domain.value_objects.exposure_vos import AssetRef
from exposure.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from collections.abc import Callable

    from exposure.application.ports.i_unit_of_work import IUnitOfWork
    from exposure.domain.ports.i_business_impact_query_port import IBusinessImpactQueryPort
    from exposure.infrastructure.repositories.threat_actor_match_cache_repository import (
        IThreatActorMatchCacheRepository,
    )


class ExposureScopeService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        cache_repo: IThreatActorMatchCacheRepository | None = None,
        business_impact_port: IBusinessImpactQueryPort | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._cache_repo = cache_repo
        self._bim = business_impact_port

    async def query_scope(
        self,
        *,
        tenant_id: TenantId,
        actor_roles: tuple[str, ...],
        max_assets: int = 100,
        min_exposure_score: float | None = None,
        amplifier_filter: list[str] | None = None,
        asset_kind_filter: list[str] | None = None,
        include_stale_scores: bool = False,
    ) -> dict[str, object]:
        del asset_kind_filter
        require_at_least(actor_roles, ExposureRole.VIEWER)
        started = datetime.now(UTC)
        tenant = tenant_id
        max_assets = max(1, min(max_assets, 1000))
        amp_filter = set(amplifier_filter or [])

        async with self._uow_factory() as uow:
            profile = await uow.profiles.load(tenant)
            cfg = await uow.weights.find_current(tenant)
            score_version = str(cfg.version) if cfg else "0"
            ranked = sorted(profile.asset_scores.items(), key=lambda kv: kv[1], reverse=True)
            assets_out: list[dict[str, object]] = []
            has_stale = False
            eligible = 0

            for asset_id_str, score in ranked:
                if min_exposure_score is not None and score < min_exposure_score:
                    continue
                asset_uuid = UUID(asset_id_str)
                snap = await uow.snapshots.find_latest_by_asset(tenant, asset_uuid)
                records = await uow.records.find_by_asset(tenant, AssetRef(asset_uuid))
                weights: dict[str, float] = {}
                for rec in records:
                    for amp in rec.active_amplifiers():
                        key = amp.type.value
                        weights[key] = weights.get(key, 0.0) + float(amp.applied_weight or 0)
                dominant = [
                    k for k, _ in sorted(weights.items(), key=lambda x: x[1], reverse=True)[:3]
                ]
                if amp_filter and not amp_filter.intersection(weights):
                    continue
                eligible += 1
                is_stale = False
                computed_at = started.isoformat()
                if snap is not None:
                    computed_at = snap.computed_at.isoformat()
                if is_stale and not include_stale_scores:
                    has_stale = True
                    continue
                if len(assets_out) >= max_assets:
                    continue
                criticality: str | None = None
                if self._bim is not None:
                    criticality = await self._bim.get_criticality(tenant, asset_uuid)
                assets_out.append(
                    {
                        "asset_ref_id": asset_id_str,
                        "exposure_score": score,
                        "dominant_amplifiers": dominant,
                        "business_criticality": criticality,
                        "snapshot_computed_at": computed_at,
                        "is_score_stale": is_stale,
                    }
                )

            duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
            stale_warning = False
            if self._cache_repo is not None:
                cache = await self._cache_repo.load(tenant)
                stale_warning = cache.is_stale()
            return {
                "tenant_id": str(tenant_id),
                "assets": assets_out,
                "total_eligible": eligible,
                "score_version": score_version,
                "queried_at": started.isoformat(),
                "has_stale_scores": has_stale or stale_warning,
                "query_duration_ms": duration_ms,
            }

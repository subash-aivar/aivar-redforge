"""ACL adapter — reads exposure scores/amplifiers for reporting."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure_reporting.application.ports.i_exposure_data_query_port import (
    ExposureDataSnapshot,
    ExposureSnapshotPoint,
    IExposureDataQueryPort,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from exposure.application.ports.i_unit_of_work import IUnitOfWork
    from exposure.infrastructure.repositories.threat_actor_match_cache_repository import (
        IThreatActorMatchCacheRepository,
    )


class ExposureDataQueryAdapter(IExposureDataQueryPort):
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        cache_repo: IThreatActorMatchCacheRepository | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._cache_repo = cache_repo

    async def load_snapshot(self, tenant_id: UUID) -> ExposureDataSnapshot:
        from exposure.domain.value_objects.identifiers import TenantId as ExpTenantId

        tenant = ExpTenantId(tenant_id)
        async with self._uow_factory() as uow:
            profile = await uow.profiles.load(tenant)
            cfg = await uow.weights.find_current(tenant)
            version = int(cfg.version) if cfg else 1
            page = await uow.records.find_active_by_tenant(tenant, 1, 100_000)
            prevalence: dict[str, float] = {}
            for rec in page.items:
                for amp in rec.active_amplifiers():
                    key = amp.type.value
                    w = float(amp.applied_weight or 0.0)
                    prevalence[key] = prevalence.get(key, 0.0) + w
            history: list[ExposureSnapshotPoint] = []
            # Sample latest snapshots from profile assets
            for asset_id in list(profile.asset_scores.keys())[:50]:
                from uuid import UUID as _UUID

                snap = await uow.snapshots.find_latest_by_asset(tenant, _UUID(asset_id))
                if snap is not None:
                    history.append(
                        ExposureSnapshotPoint(
                            asset_ref_id=asset_id,
                            composite_score=snap.composite_score,
                            computed_at=snap.computed_at.isoformat(),
                            score_input_version=int(snap.score_input_version.value),
                        )
                    )
            stale = False
            if self._cache_repo is not None:
                cache = await self._cache_repo.load(tenant)
                stale = cache.is_stale()
            return ExposureDataSnapshot(
                asset_scores=dict(profile.asset_scores),
                amplifier_weight_prevalence=prevalence,
                score_input_version=version,
                snapshot_history=tuple(history),
                threat_cache_stale=stale,
            )


class StaticExposureDataQueryAdapter(IExposureDataQueryPort):
    """Seedable stub for unit tests."""

    def __init__(
        self,
        *,
        asset_scores: dict[str, float] | None = None,
        amplifier_weight_prevalence: dict[str, float] | None = None,
        score_input_version: int = 1,
        threat_cache_stale: bool = False,
        snapshot_history: tuple[ExposureSnapshotPoint, ...] = (),
    ) -> None:
        self._asset_scores = asset_scores or {}
        self._prevalence = amplifier_weight_prevalence or {}
        self._version = score_input_version
        self._stale = threat_cache_stale
        self._history = snapshot_history

    async def load_snapshot(self, tenant_id: UUID) -> ExposureDataSnapshot:
        del tenant_id
        return ExposureDataSnapshot(
            asset_scores=dict(self._asset_scores),
            amplifier_weight_prevalence=dict(self._prevalence),
            score_input_version=self._version,
            snapshot_history=self._history,
            threat_cache_stale=self._stale,
        )

"""ThreatActorMatchSyncService — hybrid M21 event + poll (Phase 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from exposure.domain.value_objects.enums import ExposureStatus, RiskAmplifierType
from exposure.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from exposure.application.ports.i_event_publisher import IEventPublisher
    from exposure.application.ports.i_unit_of_work import IUnitOfWork
    from exposure.domain.ports.i_threat_intelligence_query_port import (
        IThreatIntelligenceQueryPort,
    )
    from exposure.infrastructure.repositories.threat_actor_match_cache_repository import (
        IThreatActorMatchCacheRepository,
    )


class ThreatActorMatchSyncService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        threat_port: IThreatIntelligenceQueryPort,
        cache_repo: IThreatActorMatchCacheRepository,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        self._threat_port = threat_port
        self._cache_repo = cache_repo

    async def apply_targeting_event(
        self,
        *,
        tenant_id: TenantId,
        event_id: str,
        threat_actor_ref: str,
        targeted_cve_ids: list[str],
        targeted_asset_classes: list[str],
        targeted_techniques: list[str] | None = None,
        targeted_iocs: list[str] | None = None,
        confidence: str = "Medium",
    ) -> int:
        """Primary path: ThreatActorAssetClassTargetingUpdated."""
        del confidence
        tenant = tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, event_id):
                return 0
            cache = await self._cache_repo.load(tenant)
            cache.apply_targeting(
                threat_actor_ref=threat_actor_ref,
                cve_ids=targeted_cve_ids,
                asset_classes=targeted_asset_classes,
                techniques=targeted_techniques,
                iocs=targeted_iocs,
                at=now,
                from_event=True,
            )
            await self._cache_repo.save(tenant, cache)
            attached = await self._attach_amplifiers(
                uow,
                tenant,
                threat_actor_ref=threat_actor_ref,
                cve_ids=targeted_cve_ids,
                asset_classes=targeted_asset_classes,
                now=now,
            )
            await uow.processed_signals.mark_processed(tenant, event_id)
            await uow.commit()
            return attached

    async def poll_and_refresh(self, tenant_id: TenantId) -> dict[str, object]:
        """Fallback path: daily poll via IThreatIntelligenceQueryPort."""
        tenant = tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            cache = await self._cache_repo.load(tenant)
            # Collect correlation keys from active records
            page = await uow.records.find_active_by_tenant(tenant, 1, 100_000)
            cve_ids: set[str] = set()
            asset_classes: set[str] = set()
            for rec in page.items:
                cve_ids.update(rec.cve_ids)
                asset_classes.update(rec.asset_classes)
            try:
                result = await self._threat_port.query_threat_actor_matches(
                    tenant, sorted(cve_ids), sorted(asset_classes)
                )
            except Exception:
                # Retain amplifiers; staleness computed from timestamps
                return {
                    "ok": False,
                    "is_stale": cache.is_stale(now),
                    "attached": 0,
                }
            attached = 0
            for match in result.matches:
                cache.apply_targeting(
                    threat_actor_ref=match.threat_actor_ref,
                    cve_ids=list(match.matched_cve_ids),
                    asset_classes=list(match.matched_asset_classes),
                    techniques=list(match.matched_techniques),
                    iocs=list(match.matched_iocs),
                    at=now,
                    from_event=False,
                )
                attached += await self._attach_amplifiers(
                    uow,
                    tenant,
                    threat_actor_ref=match.threat_actor_ref,
                    cve_ids=list(match.matched_cve_ids),
                    asset_classes=list(match.matched_asset_classes),
                    now=now,
                )
            await self._cache_repo.save(tenant, cache)
            await uow.commit()
            return {
                "ok": True,
                "is_stale": cache.is_stale(now),
                "attached": attached,
                "match_count": len(result.matches),
            }

    async def bootstrap_if_cold(self, tenant_id: TenantId) -> dict[str, object]:
        tenant = tenant_id
        cache = await self._cache_repo.load(tenant)
        if cache.last_event_update_at is None and cache.last_poll_update_at is None:
            return await self.poll_and_refresh(tenant_id)
        return {"ok": True, "is_stale": cache.is_stale(), "attached": 0, "cold": False}

    async def get_cache(self, tenant_id: TenantId) -> dict[str, object]:
        tenant = tenant_id
        cache = await self._cache_repo.load(tenant)
        return cache.to_dict()

    async def _attach_amplifiers(
        self,
        uow: IUnitOfWork,
        tenant: TenantId,
        *,
        threat_actor_ref: str,
        cve_ids: list[str],
        asset_classes: list[str],
        now: datetime,
    ) -> int:
        from exposure.domain.aggregates.amplifier_weight_configuration import (
            AmplifierWeightConfiguration,
        )
        from exposure.domain.value_objects.identifiers import AmplifierWeightConfigurationId

        cfg = await uow.weights.find_current(tenant)
        if cfg is None:
            cfg = AmplifierWeightConfiguration.create_default(
                AmplifierWeightConfigurationId.generate(), tenant, now
            )
            await uow.weights.save(tenant, cfg)
        weight = cfg.weight_for(RiskAmplifierType.THREAT_ACTOR_MATCH)
        cve_set = set(cve_ids)
        class_set = set(asset_classes)
        page = await uow.records.find_active_by_tenant(tenant, 1, 100_000)
        attached = 0
        assets: set[UUID] = set()
        for rec in page.items:
            if rec.status != ExposureStatus.ACTIVE:
                continue
            if not (cve_set.intersection(rec.cve_ids) or class_set.intersection(rec.asset_classes)):
                continue
            rec.attach_amplifier(
                tenant,
                RiskAmplifierType.THREAT_ACTOR_MATCH,
                threat_actor_ref,
                weight,
                now,
            )
            await uow.records.save(tenant, rec)
            await self._events.publish_batch(rec.pop_events())
            assets.add(rec.asset_ref.asset_ref_id)
            attached += 1
        for asset_id in assets:
            await uow.pending.upsert(tenant, asset_id, now)
        return attached

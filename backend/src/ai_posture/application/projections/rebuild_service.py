"""Projection rebuild / repair / refresh — Phase 5 background worker entrypoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from ai_posture.application._auth import require_at_least
from ai_posture.domain.events.posture_events import (
    AIComplianceMappingRecorded,
    AIRiskScoreComputed,
    AISystemAssetRegistered,
    ShadowAIAlertRaised,
)
from ai_posture.domain.value_objects.enums import AIPostureRole
from ai_posture.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
    from ai_posture.application.projections.projection_service import M31ProjectionService
    from ai_posture.application.projections.read_model_store import IReadModelStore
    from ai_posture.domain.ports.i_agent_deviation_stats_port import (
        IAgentDeviationStatsPort,
    )
    from ai_posture.domain.ports.i_discovery_scan_facts_port import IDiscoveryScanFactsPort
    from ai_posture.domain.ports.i_provenance_integrity_query_port import (
        IProvenanceIntegrityQueryPort,
    )


class ProjectionRebuildService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        store: IReadModelStore,
        projections: M31ProjectionService,
        provenance_port: IProvenanceIntegrityQueryPort,
        agent_port: IAgentDeviationStatsPort,
        discovery_port: IDiscoveryScanFactsPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._store = store
        self._projections = projections
        self._provenance = provenance_port
        self._agent = agent_port
        self._discovery = discovery_port

    async def rebuild_tenant(self, tenant_id: UUID, actor_roles: tuple[str, ...]) -> dict[str, Any]:
        require_at_least(actor_roles, AIPostureRole.ADMIN)
        tenant = TenantId(tenant_id)
        tid = str(tenant_id)
        await self._store.clear_tenant(tid)
        self._projections._seen.clear()

        async with self._uow_factory() as uow:
            assets = await uow.assets.find_all(tenant)
            for asset in assets:
                if asset.ai_system_kind is None:
                    continue
                await self._projections.apply(
                    AISystemAssetRegistered(
                        event_id=str(uuid4()),
                        occurred_at=datetime.now(UTC),
                        tenant_id=tenant,
                        aggregate_id=str(asset.asset_id),
                        aggregate_type="AISystemAsset",
                        ai_system_kind=asset.ai_system_kind.value,
                    )
                )
                snap = await uow.snapshots.find_latest_by_asset(asset.asset_id, tenant)
                if snap is not None:
                    await self._projections.apply(
                        AIRiskScoreComputed(
                            event_id=str(uuid4()),
                            occurred_at=snap.computed_at,
                            tenant_id=tenant,
                            aggregate_id=str(snap.snapshot_id),
                            aggregate_type="AIRiskScoreSnapshot",
                            ai_system_asset_id=str(snap.ai_system_asset_id),
                            composite_score=snap.composite_score,
                            score_input_version=snap.score_input_version,
                        )
                    )
                for mapping in await uow.compliance_mappings.find_by_asset(asset.asset_id, tenant):
                    await self._projections.apply(
                        AIComplianceMappingRecorded(
                            event_id=str(uuid4()),
                            occurred_at=mapping.recorded_at,
                            tenant_id=tenant,
                            aggregate_id=str(mapping.mapping_id),
                            aggregate_type="AIComplianceMapping",
                            ai_system_asset_id=str(mapping.ai_system_asset_id),
                            framework_id=mapping.framework_ref.framework_id.value,
                            control_id=mapping.framework_ref.control_id,
                            control_status=mapping.control_status.value,
                            requires_human_attestation=mapping.requires_human_attestation,
                            evaluation_mode=mapping.evaluation_mode.value,
                        )
                    )
            # Alerts: scan open alerts via fingerprint index when available
            if hasattr(uow.alerts, "items"):
                for alert in uow.alerts.items.values():
                    if alert.tenant_id != tenant:
                        continue
                    await self._projections.apply(
                        ShadowAIAlertRaised(
                            event_id=str(uuid4()),
                            occurred_at=datetime.now(UTC),
                            tenant_id=tenant,
                            aggregate_id=str(alert.alert_id),
                            aggregate_type="ShadowAIAlert",
                            fingerprint_hash=alert.fingerprint.fingerprint_hash,
                            discovery_source=alert.fingerprint.discovery_source.value,
                        )
                    )

        for row in await self._provenance.list_integrity_rows(tenant):
            await self._projections.apply_fact(tid, "provenance", row)
        for row in await self._agent.list_deviation_summaries(tenant):
            await self._projections.apply_fact(tid, "deviation", row)
        scan = await self._discovery.latest_scan_summary(tenant)
        if scan is not None:
            await self._projections.apply_fact(tid, "discovery_scan", dict(scan))
        else:
            sources = await self._discovery.configured_sources(tenant)
            if sources:
                await self._projections.apply_fact(
                    tid,
                    "discovery_scan",
                    {
                        "event_id": f"sources:{tid}",
                        "sources": sources,
                        "coverage_scope": "configured_sources_only",
                        "partial": False,
                        "failed_partitions": [],
                    },
                )
        return {
            "tenant_id": tid,
            "store": self._store.status(),
            "markers": await self._projections.rebuild_markers(),
        }

    async def refresh_cache(self, tenant_id: UUID) -> dict[str, Any]:
        """Lightweight cache refresh — reloads store status for observability."""
        return {
            "tenant_id": str(tenant_id),
            "store": self._store.status(),
            "refreshed_at": datetime.now(UTC).isoformat(),
        }

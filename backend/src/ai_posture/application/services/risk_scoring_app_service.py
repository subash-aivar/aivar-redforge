"""Risk scoring application service — Phase 2 + Phase 5 ACL wiring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from ai_posture.application._auth import require_at_least
from ai_posture.application.commands.posture_commands import (
    ComputeRiskScoreCommand,
    RunStalenessSweepCommand,
)
from ai_posture.application.dtos.posture_dtos import (
    AIRiskScoreSnapshotDTO,
    StalenessSweepResultDTO,
)
from ai_posture.application.exceptions import ApplicationNotFoundError
from ai_posture.domain.aggregates.ai_risk_score_snapshot import AIRiskScoreSnapshot
from ai_posture.domain.services.ai_risk_scoring_service import AIRiskScoringService
from ai_posture.domain.value_objects.enums import AIPostureRole
from ai_posture.domain.value_objects.identifiers import (
    AIRiskScoreSnapshotId,
    AISystemAssetId,
    TenantId,
)
from ai_posture.domain.value_objects.posture_vos import EXPOSURE_SCORE, AIRiskScoreRef
from ai_posture.infrastructure.observability.metrics import METRICS

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ai_posture.application.ports.i_event_publisher import IEventPublisher
    from ai_posture.application.ports.i_unit_of_work import IUnitOfWork
    from ai_posture.domain.ports.i_agent_deviation_stats_port import (
        IAgentDeviationStatsPort,
    )
    from ai_posture.domain.ports.i_provenance_integrity_query_port import (
        IProvenanceIntegrityQueryPort,
    )


def _to_dto(snap: AIRiskScoreSnapshot, *, now: datetime) -> AIRiskScoreSnapshotDTO:
    c = snap.score_components
    return AIRiskScoreSnapshotDTO(
        snapshot_id=str(snap.snapshot_id),
        tenant_id=str(snap.tenant_id),
        ai_system_asset_id=str(snap.ai_system_asset_id),
        composite_score=snap.composite_score,
        score_input_version=snap.score_input_version,
        is_stale=snap.is_stale(now),
        components={
            "threat_exposure_component": c.threat_exposure_component,
            "provenance_integrity_component": c.provenance_integrity_component,
            "compliance_gap_component": c.compliance_gap_component,
            "agent_deviation_component": c.agent_deviation_component,
        },
        computed_at=snap.computed_at,
    )


def _provenance_component(status: str | None) -> float:
    if status is None:
        return 40.0
    mapping = {
        "Verified": 0.0,
        "Unverified": 35.0,
        "VerificationFailed": 55.0,
        "Mismatched": 90.0,
    }
    return mapping.get(status, 40.0)


def _deviation_component(count: int) -> float:
    if count <= 0:
        return 0.0
    if count <= 2:
        return 25.0
    if count <= 5:
        return 50.0
    return min(100.0, 20.0 * count)


def _gap_component(gap_count: int) -> float:
    return min(100.0, float(gap_count) * 20.0)


class RiskScoringApplicationService:
    """Computes and stores snapshots asynchronously — never from GET handlers."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        *,
        provenance_port: IProvenanceIntegrityQueryPort | None = None,
        agent_port: IAgentDeviationStatsPort | None = None,
        gap_count_fn: Callable[[UUID, UUID], Awaitable[int]] | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._scorer = AIRiskScoringService()
        self._provenance = provenance_port
        self._agent = agent_port
        self._gap_count_fn = gap_count_fn

    async def compute(self, cmd: ComputeRiskScoreCommand) -> AIRiskScoreSnapshotDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            asset = await uow.assets.find_by_id(AISystemAssetId(cmd.asset_id), tenant)
            if asset is None:
                raise ApplicationNotFoundError("AISystemAsset", str(cmd.asset_id))
            profile = await uow.profiles.find_by_asset(asset.asset_id, tenant)
            threat_score = 0.0
            if profile is not None:
                threat_score = EXPOSURE_SCORE[profile.max_exposure_level()]

            provenance_score = 0.0
            if self._provenance is not None:
                status = await self._provenance.get_integrity_status(tenant, cmd.asset_id)
                provenance_score = _provenance_component(status)

            if self._gap_count_fn is not None:
                gaps = await self._gap_count_fn(cmd.tenant_id, cmd.asset_id)
            else:
                gaps = await uow.compliance_mappings.count_gaps_for_asset(asset.asset_id, tenant)
            gap_score = _gap_component(gaps)

            deviation_score = 0.0
            if self._agent is not None:
                count = await self._agent.recent_deviation_count(tenant, cmd.asset_id)
                deviation_score = _deviation_component(count)

            components = self._scorer.build_components(
                max_exposure_score=threat_score,
                provenance_integrity_component=provenance_score,
                compliance_gap_component=gap_score,
                agent_deviation_component=deviation_score,
            )
            snap = AIRiskScoreSnapshot.create(
                snapshot_id=AIRiskScoreSnapshotId.generate(),
                tenant_id=tenant,
                ai_system_asset_id=asset.asset_id,
                components=components,
                now=now,
            )
            asset.attach_risk_score_ref(tenant, AIRiskScoreRef(snap.snapshot_id), now)
            await uow.snapshots.save(snap)
            await uow.assets.save(asset)
            await uow.commit()
            events = snap.pop_events() + asset.pop_events()
            await self._publisher.publish_batch(events)
        METRICS.risk_scores_computed_total += 1
        return _to_dto(snap, now=now)

    async def get_latest(self, tenant_id: UUID, asset_id: UUID) -> AIRiskScoreSnapshotDTO | None:
        """Read path — returns cached snapshot only; never computes."""
        tenant = TenantId(tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            snap = await uow.snapshots.find_latest_by_asset(AISystemAssetId(asset_id), tenant)
        if snap is None:
            return None
        return _to_dto(snap, now=now)

    async def run_staleness_sweep(self, cmd: RunStalenessSweepCommand) -> StalenessSweepResultDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        flagged = 0
        recomputed = 0
        details: dict[str, object] = {}
        async with self._uow_factory() as uow:
            stale_profiles = await uow.profiles.find_stale(cmd.threat_threshold_days, tenant)
            for profile in stale_profiles:
                days = cmd.threat_threshold_days
                if profile.last_assessed_at is not None:
                    days = max(days, (now - profile.last_assessed_at).days)
                profile.flag_stale(tenant, days, now)
                await uow.profiles.save(profile)
                flagged += 1
            stale_asset_ids = await uow.snapshots.find_stale_asset_ids(timedelta(hours=24), tenant)
            details["stale_asset_ids"] = [str(a) for a in stale_asset_ids]
            await uow.commit()
            for profile in stale_profiles:
                await self._publisher.publish_batch(profile.pop_events())
        for asset_id in stale_asset_ids:
            await self.compute(
                ComputeRiskScoreCommand(
                    tenant_id=cmd.tenant_id,
                    asset_id=asset_id.value,
                    actor_roles=cmd.actor_roles,
                )
            )
            recomputed += 1
        return StalenessSweepResultDTO(
            profiles_flagged=flagged,
            scores_recomputed=recomputed,
            details=details,
        )

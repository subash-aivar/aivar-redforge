"""Four-stage score pipeline: Debounce → Dispatch → Computation (Finalization D2)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from exposure.domain.aggregates.amplifier_weight_configuration import (
    AmplifierWeightConfiguration,
)
from exposure.domain.aggregates.exposure_score_snapshot import ExposureScoreSnapshot
from exposure.domain.events.exposure_events import ExposureScoreComputed
from exposure.domain.services.exposure_score_formula import (
    compute_asset_composite,
    compute_record_score,
)
from exposure.domain.services.job_idempotency import (
    derive_job_id,
    dispatch_window_bucket,
)
from exposure.domain.value_objects.enums import ExposureStatus
from exposure.domain.value_objects.exposure_vos import AssetRef, ScoreInputVersion
from exposure.domain.value_objects.identifiers import (
    AmplifierWeightConfigurationId,
    ExposureScoreSnapshotId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from exposure.application.ports.i_event_publisher import IEventPublisher
    from exposure.application.ports.i_unit_of_work import IUnitOfWork


@dataclass(frozen=True, slots=True)
class ScoreRecomputationJob:
    job_id: str
    tenant_id: TenantId
    asset_ref_id: UUID
    dispatched_at: datetime


class RecomputationDebouncerService:
    def __init__(self, uow_factory: Callable[[], IUnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def mark(
        self,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        *,
        debounce_override_seconds: int | None = None,
        bypass: bool = False,
    ) -> None:
        tenant = tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            await uow.pending.upsert(
                tenant,
                asset_ref_id,
                now,
                debounce_override_seconds=debounce_override_seconds,
                bypass_debounce=bypass,
            )
            await uow.commit()

    async def list_eligible(
        self, *, default_debounce_seconds: int = 300, limit: int = 1000
    ) -> list[tuple[UUID, UUID]]:
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            rows = await uow.pending.list_eligible(
                now, default_debounce_seconds=default_debounce_seconds, limit=limit
            )
            return [(r.tenant_id, r.asset_ref_id) for r in rows]


class RecomputationDispatcherService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        *,
        per_tenant_rate_limit: int = 1000,
        global_ceiling: int = 5000,
        backpressure_threshold: int = 10_000,
    ) -> None:
        self._uow_factory = uow_factory
        self._per_tenant = per_tenant_rate_limit
        self._global = global_ceiling
        self._backpressure = backpressure_threshold
        self._paused = False
        self._queue_depth = 0
        self._tenant_dispatched: dict[UUID, int] = {}

    @property
    def paused(self) -> bool:
        return self._paused

    def set_queue_depth(self, depth: int) -> None:
        self._queue_depth = depth
        if depth > self._backpressure:
            self._paused = True
        elif depth < self._backpressure * 0.5:
            self._paused = False

    async def dispatch(
        self, *, default_debounce_seconds: int = 300, limit: int = 1000
    ) -> list[ScoreRecomputationJob]:
        if self._paused:
            return []
        now = datetime.now(UTC)
        jobs: list[ScoreRecomputationJob] = []
        async with self._uow_factory() as uow:
            eligible = await uow.pending.list_eligible(
                now, default_debounce_seconds=default_debounce_seconds, limit=limit
            )
            global_count = 0
            tenant_counts: dict[UUID, int] = {}
            for row in eligible:
                if global_count >= self._global:
                    break
                tcount = tenant_counts.get(row.tenant_id, 0)
                if tcount >= self._per_tenant:
                    continue
                job_id = derive_job_id(row.tenant_id, row.asset_ref_id, now)
                jobs.append(
                    ScoreRecomputationJob(
                        job_id=job_id,
                        tenant_id=row.tenant_id,
                        asset_ref_id=row.asset_ref_id,
                        dispatched_at=now,
                    )
                )
                await uow.pending.delete(row.tenant_id, row.asset_ref_id)
                tenant_counts[row.tenant_id] = tcount + 1
                global_count += 1
            await uow.commit()
        self._queue_depth += len(jobs)
        self.set_queue_depth(self._queue_depth)
        return jobs


class ExposureScoreComputationWorker:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher

    async def compute(self, job: ScoreRecomputationJob) -> ExposureScoreSnapshot | None:
        tenant = job.tenant_id
        now = datetime.now(UTC)
        bucket_start = dispatch_window_bucket(job.dispatched_at)
        async with self._uow_factory() as uow:
            if await uow.snapshots.exists_after(tenant, job.asset_ref_id, bucket_start):
                return None  # idempotent skip
            cfg = await uow.weights.find_current(tenant)
            if cfg is None:
                cfg = AmplifierWeightConfiguration.create_default(
                    AmplifierWeightConfigurationId.generate(), tenant, now
                )
                await uow.weights.save(tenant, cfg)
            records = await uow.records.find_by_asset(tenant, AssetRef(job.asset_ref_id))
            active = [r for r in records if r.status == ExposureStatus.ACTIVE]
            record_scores: dict[str, float] = {}
            scores: list[float] = []
            for record in active:
                score = compute_record_score(record, cfg)
                record.set_denormalized_score(score)
                await uow.records.save(tenant, record)
                record_scores[str(record.record_id)] = score
                scores.append(score)
            composite = compute_asset_composite(scores)
            snapshot = ExposureScoreSnapshot.create(
                ExposureScoreSnapshotId.generate(),
                tenant,
                job.asset_ref_id,
                composite,
                ScoreInputVersion(cfg.version),
                now,
                job.job_id,
                record_scores,
            )
            await uow.snapshots.save(tenant, snapshot)
            profile = await uow.profiles.load(tenant)
            profile.asset_scores[str(job.asset_ref_id)] = composite
            if await uow.pending.count_for_tenant(tenant) == 0:
                profile.recomputing = False
            profile.recomputation_failed_at = None
            await uow.profiles.save(tenant, profile)
            await uow.commit()
            event = ExposureScoreComputed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=str(snapshot.snapshot_id),
                aggregate_type="ExposureScoreSnapshot",
                asset_ref_id=str(job.asset_ref_id),
                composite_score=composite,
                score_input_version=cfg.version,
                job_id=job.job_id,
            )
            await self._events.publish_batch([event])
            return snapshot

    async def run_pipeline_once(
        self,
        debouncer: RecomputationDebouncerService,
        dispatcher: RecomputationDispatcherService,
        *,
        debounce_seconds: int = 0,
    ) -> int:
        """Convenience for tests: dispatch eligible + compute. debounce_seconds=0 for immediate."""
        del debouncer  # eligibility is read inside dispatcher
        jobs = await dispatcher.dispatch(default_debounce_seconds=debounce_seconds)
        computed = 0
        for job in jobs:
            if await self.compute(job) is not None:
                computed += 1
                dispatcher.set_queue_depth(max(0, dispatcher._queue_depth - 1))
        return computed

"""In-memory UoW + repositories for exposure Phase 1/2."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure.application.ports.i_pipeline_stores import (
    IPendingRecomputationStore,
    IProcessedExposureSignalStore,
    ITenantExposureProfileStore,
    PendingRecomputation,
    TenantExposureProfile,
)
from exposure.application.ports.i_unit_of_work import IUnitOfWork
from exposure.domain.exceptions.domain_exceptions import TenantContextMissingError
from exposure.domain.repositories.i_amplifier_weight_configuration_repository import (
    IAmplifierWeightConfigurationRepository,
)
from exposure.domain.repositories.i_exposure_record_repository import (
    IExposureRecordRepository,
    Page,
)
from exposure.domain.repositories.i_exposure_score_snapshot_repository import (
    IExposureScoreSnapshotRepository,
)
from exposure.domain.value_objects.enums import ExposureStatus

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from exposure.domain.aggregates.amplifier_weight_configuration import (
        AmplifierWeightConfiguration,
    )
    from exposure.domain.aggregates.exposure_record import ExposureRecord
    from exposure.domain.aggregates.exposure_score_snapshot import ExposureScoreSnapshot
    from exposure.domain.value_objects.enums import RiskAmplifierType, SignalDomain
    from exposure.domain.value_objects.exposure_vos import AssetRef, SignalSourceRef
    from exposure.domain.value_objects.identifiers import (
        ExposureRecordId,
        TenantId,
    )


def _require_tenant(tenant_id: TenantId | None) -> TenantId:
    if tenant_id is None:
        raise TenantContextMissingError()
    return tenant_id


class InMemoryExposureRecordRepository(IExposureRecordRepository):
    def __init__(self) -> None:
        self.items: dict[str, ExposureRecord] = {}
        self.technique_index: dict[tuple[str, str], set[str]] = {}

    def index_technique(self, tenant_id: TenantId, technique: str, record_id: str) -> None:
        self.technique_index.setdefault((str(tenant_id), technique), set()).add(record_id)

    async def find_by_id(
        self, tenant_id: TenantId, record_id: ExposureRecordId
    ) -> ExposureRecord | None:
        _require_tenant(tenant_id)
        rec = self.items.get(str(record_id))
        if rec is None or rec.tenant_id != tenant_id:
            return None
        return rec

    async def find_by_signal(
        self,
        tenant_id: TenantId,
        signal_domain: SignalDomain,
        signal_source_ref: SignalSourceRef,
    ) -> ExposureRecord | None:
        _require_tenant(tenant_id)
        for rec in self.items.values():
            if (
                rec.tenant_id == tenant_id
                and rec.signal_domain == signal_domain
                and str(rec.signal_source_ref) == str(signal_source_ref)
                and rec.status != ExposureStatus.RESOLVED
            ):
                return rec
        # Also allow finding the latest resolved for resolve path
        for rec in self.items.values():
            if (
                rec.tenant_id == tenant_id
                and rec.signal_domain == signal_domain
                and str(rec.signal_source_ref) == str(signal_source_ref)
            ):
                return rec
        return None

    async def find_by_asset(self, tenant_id: TenantId, asset_ref: AssetRef) -> list[ExposureRecord]:
        _require_tenant(tenant_id)
        return [
            r for r in self.items.values() if r.tenant_id == tenant_id and r.asset_ref == asset_ref
        ]

    async def find_active_by_tenant(self, tenant_id: TenantId, page: int, page_size: int) -> Page:
        _require_tenant(tenant_id)
        active = [
            r
            for r in self.items.values()
            if r.tenant_id == tenant_id and r.status == ExposureStatus.ACTIVE
        ]
        start = (page - 1) * page_size
        return Page(active[start : start + page_size], len(active), page, page_size)

    async def find_with_amplifier(
        self,
        tenant_id: TenantId,
        amplifier_type: RiskAmplifierType,
        page: int,
        page_size: int,
    ) -> Page:
        _require_tenant(tenant_id)
        matched = [
            r
            for r in self.items.values()
            if r.tenant_id == tenant_id
            and any(a.type == amplifier_type and a.is_active for a in r.risk_amplifiers)
        ]
        start = (page - 1) * page_size
        return Page(matched[start : start + page_size], len(matched), page, page_size)

    async def find_stale_scores(
        self, tenant_id: TenantId, stale_before: datetime
    ) -> list[ExposureRecord]:
        _require_tenant(tenant_id)
        del stale_before
        return [
            r
            for r in self.items.values()
            if r.tenant_id == tenant_id and r.status == ExposureStatus.ACTIVE
        ]

    async def find_by_technique(
        self, tenant_id: TenantId, technique_ref: str
    ) -> list[ExposureRecord]:
        _require_tenant(tenant_id)
        ids = self.technique_index.get((str(tenant_id), technique_ref), set())
        result: list[ExposureRecord] = []
        for rid in ids:
            rec = self.items.get(rid)
            if rec is not None and rec.tenant_id == tenant_id:
                result.append(rec)
        return result

    async def save(self, tenant_id: TenantId, record: ExposureRecord) -> None:
        _require_tenant(tenant_id)
        if record.tenant_id != tenant_id:
            raise TenantContextMissingError()
        self.items[str(record.record_id)] = record

    async def save_batch(self, tenant_id: TenantId, records: list[ExposureRecord]) -> None:
        for record in records:
            await self.save(tenant_id, record)


class InMemorySnapshotRepository(IExposureScoreSnapshotRepository):
    def __init__(self) -> None:
        self.items: list[ExposureScoreSnapshot] = []

    async def save(self, tenant_id: TenantId, snapshot: ExposureScoreSnapshot) -> None:
        _require_tenant(tenant_id)
        self.items.append(snapshot)

    async def find_latest_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID
    ) -> ExposureScoreSnapshot | None:
        _require_tenant(tenant_id)
        matches = [
            s for s in self.items if s.tenant_id == tenant_id and s.asset_ref_id == asset_ref_id
        ]
        if not matches:
            return None
        matches.sort(key=lambda s: s.computed_at, reverse=True)
        return matches[0]

    async def exists_after(self, tenant_id: TenantId, asset_ref_id: UUID, after: datetime) -> bool:
        _require_tenant(tenant_id)
        return any(
            s.tenant_id == tenant_id and s.asset_ref_id == asset_ref_id and s.computed_at > after
            for s in self.items
        )


class InMemoryWeightRepository(IAmplifierWeightConfigurationRepository):
    def __init__(self) -> None:
        self.items: dict[str, list[AmplifierWeightConfiguration]] = {}

    async def save(self, tenant_id: TenantId, config: AmplifierWeightConfiguration) -> None:
        _require_tenant(tenant_id)
        self.items.setdefault(str(tenant_id), []).append(config)

    async def find_current(self, tenant_id: TenantId) -> AmplifierWeightConfiguration | None:
        _require_tenant(tenant_id)
        versions = self.items.get(str(tenant_id), [])
        if not versions:
            return None
        return max(versions, key=lambda c: c.version)

    async def find_by_version(
        self, tenant_id: TenantId, version: int
    ) -> AmplifierWeightConfiguration | None:
        _require_tenant(tenant_id)
        for cfg in self.items.get(str(tenant_id), []):
            if cfg.version == version:
                return cfg
        return None

    async def find_all_versions(self, tenant_id: TenantId) -> list[AmplifierWeightConfiguration]:
        _require_tenant(tenant_id)
        return sorted(self.items.get(str(tenant_id), []), key=lambda c: c.version)


class InMemoryPendingStore(IPendingRecomputationStore):
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], PendingRecomputation] = {}

    async def upsert(
        self,
        tenant_id: TenantId,
        asset_ref_id: UUID,
        marked_at: datetime,
        *,
        debounce_override_seconds: int | None = None,
        bypass_debounce: bool = False,
    ) -> None:
        key = (str(tenant_id), str(asset_ref_id))
        existing = self.rows.get(key)
        if existing is None:
            self.rows[key] = PendingRecomputation(
                tenant_id,
                asset_ref_id,
                marked_at,
                debounce_override_seconds,
                bypass_debounce,
            )
        else:
            # upsert-on-conflict: refresh marked_at (absorbs thundering herd)
            existing.marked_at = marked_at
            if debounce_override_seconds is not None:
                existing.debounce_override_seconds = debounce_override_seconds
            if bypass_debounce:
                existing.bypass_debounce = True

    async def upsert_all_assets(
        self,
        tenant_id: TenantId,
        asset_ref_ids: list[UUID],
        marked_at: datetime,
        *,
        debounce_override_seconds: int | None = None,
    ) -> None:
        for aid in asset_ref_ids:
            await self.upsert(
                tenant_id,
                aid,
                marked_at,
                debounce_override_seconds=debounce_override_seconds,
            )

    async def list_eligible(
        self, now: datetime, default_debounce_seconds: int = 300, limit: int = 1000
    ) -> list[PendingRecomputation]:
        eligible: list[PendingRecomputation] = []
        for row in self.rows.values():
            window = (
                row.debounce_override_seconds
                if row.debounce_override_seconds is not None
                else default_debounce_seconds
            )
            if row.bypass_debounce or (now - row.marked_at).total_seconds() >= window:
                eligible.append(row)
        eligible.sort(key=lambda r: r.marked_at)
        return eligible[:limit]

    async def delete(self, tenant_id: TenantId, asset_ref_id: UUID) -> None:
        self.rows.pop((str(tenant_id), str(asset_ref_id)), None)

    async def count_for_tenant(self, tenant_id: TenantId) -> int:
        return sum(1 for k in self.rows if k[0] == str(tenant_id))

    async def flush_tenant(self, tenant_id: TenantId) -> list[UUID]:
        flushed: list[UUID] = []
        for key, row in list(self.rows.items()):
            if key[0] == str(tenant_id):
                row.bypass_debounce = True
                flushed.append(row.asset_ref_id)
        return flushed


class InMemoryProcessedSignalStore(IProcessedExposureSignalStore):
    def __init__(self) -> None:
        self.seen: set[tuple[str, str]] = set()

    async def already_processed(self, tenant_id: TenantId, event_id: str) -> bool:
        return (str(tenant_id), event_id) in self.seen

    async def mark_processed(self, tenant_id: TenantId, event_id: str) -> None:
        self.seen.add((str(tenant_id), event_id))


class InMemoryProfileStore(ITenantExposureProfileStore):
    def __init__(self) -> None:
        self.profiles: dict[str, TenantExposureProfile] = {}

    async def load(self, tenant_id: TenantId) -> TenantExposureProfile:
        key = str(tenant_id)
        if key not in self.profiles:
            self.profiles[key] = TenantExposureProfile(tenant_id=tenant_id)
        return self.profiles[key]

    async def save(self, tenant_id: TenantId, profile: TenantExposureProfile) -> None:
        self.profiles[str(tenant_id)] = profile


class InMemoryUnitOfWork(IUnitOfWork):
    def __init__(self) -> None:
        self.records = InMemoryExposureRecordRepository()
        self.snapshots = InMemorySnapshotRepository()
        self.weights = InMemoryWeightRepository()
        self.pending = InMemoryPendingStore()
        self.processed_signals = InMemoryProcessedSignalStore()
        self.profiles = InMemoryProfileStore()
        self._committed = False

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        pass

    async def __aenter__(self) -> InMemoryUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        del exc_tb
        if exc_type is not None or not self._committed:
            await self.rollback()

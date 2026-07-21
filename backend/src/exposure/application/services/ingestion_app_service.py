"""ExposureSignalIngestionService — Phase 1 (M27) + Phase 2 (M26/M28/M31)."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

from exposure.application.dtos.exposure_dtos import ExposureRecordDTO
from exposure.application.services.mappers import to_record_dto
from exposure.domain.aggregates.amplifier_weight_configuration import (
    AmplifierWeightConfiguration,
)
from exposure.domain.aggregates.exposure_record import ExposureRecord
from exposure.domain.value_objects.enums import (
    ExposureStatus,
    RiskAmplifierType,
    SignalDomain,
)
from exposure.domain.value_objects.exposure_vos import (
    AssetRef,
    ExposureLevel,
    SignalSourceRef,
)
from exposure.domain.value_objects.identifiers import (
    AmplifierWeightConfigurationId,
    ExposureRecordId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from exposure.application.commands.exposure_commands import (
        IngestAISystemRiskSignalCommand,
        IngestCloudSecuritySignalCommand,
        IngestConfirmedExploitationCommand,
        IngestDetectionGapSignalCommand,
        IngestVulnerabilitySignalCommand,
        RemediateCloudSecuritySignalCommand,
        ResolveVulnerabilitySignalCommand,
        VulnerabilityKevStatusChangedCommand,
    )
    from exposure.application.ports.i_event_publisher import IEventPublisher
    from exposure.application.ports.i_unit_of_work import IUnitOfWork


class ExposureSignalIngestionService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._events = event_publisher
        # Review R04: technique_ref → record ids for DetectionGap fan-out (P2)
        self._technique_index: dict[tuple[str, str], set[str]] = {}

    async def _ensure_weights(
        self, uow: IUnitOfWork, tenant: TenantId, now: datetime
    ) -> AmplifierWeightConfiguration:
        cfg = await uow.weights.find_current(tenant)
        if cfg is None:
            cfg = AmplifierWeightConfiguration.create_default(
                AmplifierWeightConfigurationId.generate(), tenant, now
            )
            await uow.weights.save(tenant, cfg)
        return cfg

    async def _mark_pending(
        self, uow: IUnitOfWork, tenant: TenantId, asset_ref_id: UUID, now: datetime
    ) -> None:
        await uow.pending.upsert(tenant, asset_ref_id, now)

    def _index_techniques(
        self, tenant: TenantId, record: ExposureRecord, techniques: tuple[str, ...]
    ) -> None:
        for tech in techniques:
            key = (str(tenant), tech)
            self._technique_index.setdefault(key, set()).add(str(record.record_id))

    async def ingest_vulnerability(
        self, cmd: IngestVulnerabilitySignalCommand
    ) -> ExposureRecordDTO | None:
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return None
            cfg = await self._ensure_weights(uow, tenant, now)
            source = SignalSourceRef(cmd.vulnerability_instance_id)
            existing = await uow.records.find_by_signal(
                tenant, SignalDomain.VULNERABILITY_MANAGEMENT, source
            )
            if existing is not None and existing.status == ExposureStatus.RESOLVED:
                # Identity is unique; resurrection forbidden. New occurrence needs new
                # SignalSourceRef (new VulnerabilityInstanceId).
                await uow.processed_signals.mark_processed(tenant, cmd.event_id)
                await uow.commit()
                return to_record_dto(existing)
            if existing is None:
                record = ExposureRecord.create(
                    ExposureRecordId.generate(),
                    tenant,
                    AssetRef(cmd.asset_ref_id),
                    SignalDomain.VULNERABILITY_MANAGEMENT,
                    source,
                    ExposureLevel(max(0.0, min(10.0, cmd.cvss_base))),
                    now,
                    cve_ids=list(cmd.cve_ids),
                    asset_classes=list(cmd.asset_classes),
                )
            else:
                record = existing
                record.base_exposure_level = ExposureLevel(max(0.0, min(10.0, cmd.cvss_base)))
                if cmd.cve_ids:
                    record.cve_ids = list(dict.fromkeys([*record.cve_ids, *cmd.cve_ids]))
                if cmd.asset_classes:
                    record.asset_classes = list(
                        dict.fromkeys([*record.asset_classes, *cmd.asset_classes])
                    )
                record.bump_version()
            if cmd.is_kev:
                record.attach_amplifier(
                    tenant,
                    RiskAmplifierType.KEV_PRESENT,
                    cmd.vulnerability_instance_id,
                    cfg.weight_for(RiskAmplifierType.KEV_PRESENT),
                    now,
                )
            await uow.records.save(tenant, record)
            self._index_techniques(tenant, record, cmd.technique_refs)
            await self._mark_pending(uow, tenant, cmd.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_record_dto(record)

    async def resolve_vulnerability(
        self, cmd: ResolveVulnerabilitySignalCommand
    ) -> ExposureRecordDTO | None:
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return None
            source = SignalSourceRef(cmd.vulnerability_instance_id)
            record = await uow.records.find_by_signal(
                tenant, SignalDomain.VULNERABILITY_MANAGEMENT, source
            )
            if record is None:
                await uow.processed_signals.mark_processed(tenant, cmd.event_id)
                await uow.commit()
                return None
            record.resolve(tenant, now)
            await uow.records.save(tenant, record)
            await self._mark_pending(uow, tenant, record.asset_ref.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_record_dto(record)

    async def kev_status_changed(
        self, cmd: VulnerabilityKevStatusChangedCommand
    ) -> ExposureRecordDTO | None:
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return None
            cfg = await self._ensure_weights(uow, tenant, now)
            source = SignalSourceRef(cmd.vulnerability_instance_id)
            record = await uow.records.find_by_signal(
                tenant, SignalDomain.VULNERABILITY_MANAGEMENT, source
            )
            if record is None or record.status != ExposureStatus.ACTIVE:
                await uow.processed_signals.mark_processed(tenant, cmd.event_id)
                await uow.commit()
                return None
            if cmd.is_kev:
                record.attach_amplifier(
                    tenant,
                    RiskAmplifierType.KEV_PRESENT,
                    cmd.vulnerability_instance_id,
                    cfg.weight_for(RiskAmplifierType.KEV_PRESENT),
                    now,
                )
            else:
                record.deactivate_amplifier(
                    tenant,
                    RiskAmplifierType.KEV_PRESENT,
                    cmd.vulnerability_instance_id,
                    now,
                )
            await uow.records.save(tenant, record)
            await self._mark_pending(uow, tenant, record.asset_ref.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_record_dto(record)

    async def ingest_cloud_security(
        self, cmd: IngestCloudSecuritySignalCommand
    ) -> ExposureRecordDTO | None:
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return None
            cfg = await self._ensure_weights(uow, tenant, now)
            source = SignalSourceRef(cmd.misconfiguration_id)
            existing = await uow.records.find_by_signal(tenant, SignalDomain.CLOUD_SECURITY, source)
            if existing is not None and existing.status == ExposureStatus.RESOLVED:
                await uow.processed_signals.mark_processed(tenant, cmd.event_id)
                await uow.commit()
                return to_record_dto(existing)
            if existing is None:
                record = ExposureRecord.create(
                    ExposureRecordId.generate(),
                    tenant,
                    AssetRef(cmd.asset_ref_id),
                    SignalDomain.CLOUD_SECURITY,
                    source,
                    ExposureLevel(max(0.0, min(10.0, cmd.severity_score))),
                    now,
                )
            else:
                record = existing
                record.base_exposure_level = ExposureLevel(max(0.0, min(10.0, cmd.severity_score)))
                record.bump_version()
            if cmd.has_internet_exposure:
                record.attach_amplifier(
                    tenant,
                    RiskAmplifierType.INTERNET_EXPOSURE,
                    cmd.misconfiguration_id,
                    cfg.weight_for(RiskAmplifierType.INTERNET_EXPOSURE),
                    now,
                )
            # Also attach CloudMisconfiguration amp onto related VulnManagement records
            vuln_records = await uow.records.find_by_asset(tenant, AssetRef(cmd.asset_ref_id))
            for vr in vuln_records:
                if (
                    vr.signal_domain == SignalDomain.VULNERABILITY_MANAGEMENT
                    and vr.status == ExposureStatus.ACTIVE
                ):
                    vr.attach_amplifier(
                        tenant,
                        RiskAmplifierType.CLOUD_MISCONFIGURATION,
                        cmd.misconfiguration_id,
                        cfg.weight_for(RiskAmplifierType.CLOUD_MISCONFIGURATION),
                        now,
                    )
                    await uow.records.save(tenant, vr)
                    await self._events.publish_batch(vr.pop_events())
            await uow.records.save(tenant, record)
            await self._mark_pending(uow, tenant, cmd.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_record_dto(record)

    async def remediate_cloud_security(
        self, cmd: RemediateCloudSecuritySignalCommand
    ) -> ExposureRecordDTO | None:
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return None
            source = SignalSourceRef(cmd.misconfiguration_id)
            record = await uow.records.find_by_signal(tenant, SignalDomain.CLOUD_SECURITY, source)
            if record is None:
                await uow.processed_signals.mark_processed(tenant, cmd.event_id)
                await uow.commit()
                return None
            record.resolve(tenant, now)
            # Deactivate CloudMisconfiguration amps on vuln records
            vuln_records = await uow.records.find_by_asset(tenant, record.asset_ref)
            for vr in vuln_records:
                if vr.signal_domain == SignalDomain.VULNERABILITY_MANAGEMENT:
                    vr.deactivate_amplifier(
                        tenant,
                        RiskAmplifierType.CLOUD_MISCONFIGURATION,
                        cmd.misconfiguration_id,
                        now,
                    )
                    await uow.records.save(tenant, vr)
            await uow.records.save(tenant, record)
            await self._mark_pending(uow, tenant, record.asset_ref.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
            await self._events.publish_batch(record.pop_events())
            return to_record_dto(record)

    async def ingest_detection_gap(self, cmd: IngestDetectionGapSignalCommand) -> int:
        """Attach DetectionGap amplifiers to matching active exposure records.

        Detection gaps never create standalone ExposureRecords (Finalization D1).
        """
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        attached = 0
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return 0
            cfg = await self._ensure_weights(uow, tenant, now)
            # Prefer technique index; fall back to asset scan
            indexed = self._technique_index.get((str(tenant), cmd.technique_ref), set())
            candidates: list[ExposureRecord] = []
            if indexed:
                for rid in indexed:
                    rec = await uow.records.find_by_id(tenant, ExposureRecordId(UUID(rid)))
                    if rec is not None and rec.status == ExposureStatus.ACTIVE:
                        candidates.append(rec)
            else:
                by_asset = await uow.records.find_by_asset(tenant, AssetRef(cmd.asset_ref_id))
                candidates = [r for r in by_asset if r.status == ExposureStatus.ACTIVE]
                # also search by technique via repo
                by_tech = await uow.records.find_by_technique(tenant, cmd.technique_ref)
                for r in by_tech:
                    if r.status == ExposureStatus.ACTIVE and r not in candidates:
                        candidates.append(r)
            assets: set[UUID] = set()
            for record in candidates:
                if cmd.is_open:
                    record.attach_amplifier(
                        tenant,
                        RiskAmplifierType.DETECTION_GAP,
                        cmd.gap_id,
                        cfg.weight_for(RiskAmplifierType.DETECTION_GAP),
                        now,
                    )
                    attached += 1
                else:
                    record.deactivate_amplifier(
                        tenant,
                        RiskAmplifierType.DETECTION_GAP,
                        cmd.gap_id,
                        now,
                    )
                await uow.records.save(tenant, record)
                assets.add(record.asset_ref.asset_ref_id)
                await self._events.publish_batch(record.pop_events())
            for asset_id in assets:
                await self._mark_pending(uow, tenant, asset_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
        return attached

    async def ingest_ai_system_risk(self, cmd: IngestAISystemRiskSignalCommand) -> int:
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        attached = 0
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return 0
            records = await uow.records.find_by_asset(tenant, AssetRef(cmd.asset_ref_id))
            weight = Decimal(str(cmd.amplifier_weight))
            for record in records:
                if record.status != ExposureStatus.ACTIVE:
                    continue
                record.attach_amplifier(
                    tenant,
                    RiskAmplifierType.AI_SYSTEM_RISK,
                    cmd.profile_ref,
                    weight,
                    now,
                )
                await uow.records.save(tenant, record)
                attached += 1
                await self._events.publish_batch(record.pop_events())
            await self._mark_pending(uow, tenant, cmd.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
        return attached

    async def ingest_confirmed_exploitation(self, cmd: IngestConfirmedExploitationCommand) -> int:
        """M29 correlation — ConfirmedExploitation amplifier on matching active records."""
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        attached = 0
        async with self._uow_factory() as uow:
            if await uow.processed_signals.already_processed(tenant, cmd.event_id):
                return 0
            cfg = await self._ensure_weights(uow, tenant, now)
            records = await uow.records.find_by_asset(tenant, AssetRef(cmd.asset_ref_id))
            for record in records:
                if record.status != ExposureStatus.ACTIVE:
                    continue
                if cmd.cve_id and cmd.cve_id not in record.cve_ids:
                    continue
                record.attach_amplifier(
                    tenant,
                    RiskAmplifierType.CONFIRMED_EXPLOITATION,
                    cmd.evidence_ref,
                    cfg.weight_for(RiskAmplifierType.CONFIRMED_EXPLOITATION),
                    now,
                )
                await uow.records.save(tenant, record)
                attached += 1
                await self._events.publish_batch(record.pop_events())
            await self._mark_pending(uow, tenant, cmd.asset_ref_id, now)
            await uow.processed_signals.mark_processed(tenant, cmd.event_id)
            await uow.commit()
        return attached

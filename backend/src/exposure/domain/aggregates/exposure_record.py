"""ExposureRecord aggregate root — ADR-M32-001 signal-scoped identity."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import uuid4

from exposure.domain.entities.risk_amplifier import RiskAmplifier
from exposure.domain.events.exposure_events import (
    ExposureRecordCreated,
    ExposureRecordResolved,
    ExposureRecordSuppressed,
    RiskAmplifierAttached,
    RiskAmplifierDeactivated,
)
from exposure.domain.exceptions.domain_exceptions import (
    InvalidExposureTransition,
    ResolvedAtImmutable,
    SuppressionJustificationRequired,
    TenantMismatch,
)
from exposure.domain.value_objects.enums import ExposureStatus, RiskAmplifierType
from exposure.domain.value_objects.identifiers import RiskAmplifierId

if TYPE_CHECKING:
    from datetime import datetime

    from exposure.domain.events.base import BaseDomainEvent
    from exposure.domain.value_objects.enums import SignalDomain
    from exposure.domain.value_objects.exposure_vos import AssetRef, ExposureLevel, SignalSourceRef
    from exposure.domain.value_objects.identifiers import ExposureRecordId, TenantId


class ExposureRecord:
    __slots__ = (
        "_pending_events",
        "_version",
        "asset_classes",
        "asset_ref",
        "base_exposure_level",
        "created_at",
        "current_exposure_score",
        "cve_ids",
        "record_id",
        "resolved_at",
        "risk_amplifiers",
        "signal_domain",
        "signal_source_ref",
        "status",
        "suppression_justification",
        "tenant_id",
    )

    def __init__(
        self,
        record_id: ExposureRecordId,
        tenant_id: TenantId,
        asset_ref: AssetRef,
        signal_domain: SignalDomain,
        signal_source_ref: SignalSourceRef,
        status: ExposureStatus,
        base_exposure_level: ExposureLevel,
        risk_amplifiers: list[RiskAmplifier],
        current_exposure_score: float,
        created_at: datetime,
        resolved_at: datetime | None,
        version: int,
        suppression_justification: str | None = None,
        cve_ids: list[str] | None = None,
        asset_classes: list[str] | None = None,
    ) -> None:
        self.record_id = record_id
        self.tenant_id = tenant_id
        self.asset_ref = asset_ref
        self.signal_domain = signal_domain
        self.signal_source_ref = signal_source_ref
        self.status = status
        self.base_exposure_level = base_exposure_level
        self.risk_amplifiers = list(risk_amplifiers)
        self.current_exposure_score = current_exposure_score
        self.created_at = created_at
        self.resolved_at = resolved_at
        self._version = version
        self.suppression_justification = suppression_justification
        self.cve_ids = list(cve_ids or [])
        self.asset_classes = list(asset_classes or [])
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def bump_version(self) -> None:
        self._version += 1

    @classmethod
    def create(
        cls,
        record_id: ExposureRecordId,
        tenant_id: TenantId,
        asset_ref: AssetRef,
        signal_domain: SignalDomain,
        signal_source_ref: SignalSourceRef,
        base_exposure_level: ExposureLevel,
        now: datetime,
        *,
        cve_ids: list[str] | None = None,
        asset_classes: list[str] | None = None,
    ) -> ExposureRecord:
        record = cls(
            record_id=record_id,
            tenant_id=tenant_id,
            asset_ref=asset_ref,
            signal_domain=signal_domain,
            signal_source_ref=signal_source_ref,
            status=ExposureStatus.ACTIVE,
            base_exposure_level=base_exposure_level,
            risk_amplifiers=[],
            current_exposure_score=base_exposure_level.value,
            created_at=now,
            resolved_at=None,
            version=1,
            cve_ids=cve_ids,
            asset_classes=asset_classes,
        )
        record._emit(
            ExposureRecordCreated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(record_id),
                aggregate_type="ExposureRecord",
                asset_ref_id=str(asset_ref.asset_ref_id),
                signal_domain=signal_domain,
                signal_source_ref=str(signal_source_ref),
            )
        )
        return record

    def attach_amplifier(
        self,
        tenant_id: TenantId,
        amplifier_type: RiskAmplifierType,
        source_ref: str,
        weight: Decimal,
        now: datetime,
    ) -> RiskAmplifier:
        self._assert_tenant(tenant_id)
        if self.status == ExposureStatus.RESOLVED:
            raise InvalidExposureTransition(self.status.value, "attach_amplifier")
        for existing in self.risk_amplifiers:
            if existing.type == amplifier_type and existing.source_ref == source_ref:
                existing.confirm(now)
                existing.applied_weight = weight
                self.bump_version()
                return existing
        amp = RiskAmplifier(
            amplifier_id=RiskAmplifierId.generate(),
            type=amplifier_type,
            source_ref=source_ref,
            first_observed_at=now,
            last_confirmed_at=now,
            applied_weight=weight,
            is_active=True,
        )
        self.risk_amplifiers.append(amp)
        self.bump_version()
        self._emit(
            RiskAmplifierAttached(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.record_id),
                aggregate_type="ExposureRecord",
                amplifier_type=amplifier_type,
                source_ref=source_ref,
            )
        )
        return amp

    def deactivate_amplifier(
        self,
        tenant_id: TenantId,
        amplifier_type: RiskAmplifierType,
        source_ref: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        for amp in self.risk_amplifiers:
            if amp.type == amplifier_type and amp.source_ref == source_ref and amp.is_active:
                amp.deactivate()
                self.bump_version()
                self._emit(
                    RiskAmplifierDeactivated(
                        event_id=str(uuid4()),
                        occurred_at=now,
                        tenant_id=tenant_id,
                        aggregate_id=str(self.record_id),
                        aggregate_type="ExposureRecord",
                        amplifier_type=amplifier_type,
                        source_ref=source_ref,
                    )
                )
                return

    def resolve(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status == ExposureStatus.RESOLVED:
            return
        if self.resolved_at is not None:
            raise ResolvedAtImmutable()
        self.status = ExposureStatus.RESOLVED
        self.resolved_at = now
        self.bump_version()
        self._emit(
            ExposureRecordResolved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.record_id),
                aggregate_type="ExposureRecord",
                asset_ref_id=str(self.asset_ref.asset_ref_id),
                signal_source_ref=str(self.signal_source_ref),
            )
        )

    def suppress(
        self,
        tenant_id: TenantId,
        justification: str,
        suppressed_by: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not justification.strip():
            raise SuppressionJustificationRequired()
        if self.status == ExposureStatus.RESOLVED:
            raise InvalidExposureTransition(self.status.value, ExposureStatus.SUPPRESSED.value)
        self.status = ExposureStatus.SUPPRESSED
        self.suppression_justification = justification.strip()
        self.bump_version()
        self._emit(
            ExposureRecordSuppressed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.record_id),
                aggregate_type="ExposureRecord",
                asset_ref_id=str(self.asset_ref.asset_ref_id),
                justification=self.suppression_justification,
                suppressed_by=suppressed_by,
            )
        )

    def active_amplifiers(self) -> list[RiskAmplifier]:
        return [a for a in self.risk_amplifiers if a.is_active]

    def set_denormalized_score(self, score: float) -> None:
        self.current_exposure_score = score

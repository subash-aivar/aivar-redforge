from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

import pytest

from exposure.domain.aggregates.exposure_record import ExposureRecord
from exposure.domain.exceptions.domain_exceptions import (
    InvalidExposureTransition,
    SuppressionJustificationRequired,
)
from exposure.domain.value_objects.enums import (
    ExposureStatus,
    RiskAmplifierType,
    SignalDomain,
)
from exposure.domain.value_objects.exposure_vos import AssetRef, ExposureLevel, SignalSourceRef
from exposure.domain.value_objects.identifiers import ExposureRecordId, TenantId


def _now() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


def _record(tenant: TenantId | None = None) -> ExposureRecord:
    tenant = tenant or TenantId(uuid4())
    return ExposureRecord.create(
        ExposureRecordId.generate(),
        tenant,
        AssetRef(uuid4()),
        SignalDomain.VULNERABILITY_MANAGEMENT,
        SignalSourceRef("vuln-1"),
        ExposureLevel(7.5),
        _now(),
    )


def test_create_emits_created_event() -> None:
    rec = _record()
    events = rec.pop_events()
    assert rec.status == ExposureStatus.ACTIVE
    assert any(type(e).__name__ == "ExposureRecordCreated" for e in events)


def test_attach_and_confirm_amplifier() -> None:
    rec = _record()
    tenant = rec.tenant_id
    rec.pop_events()
    amp = rec.attach_amplifier(
        tenant, RiskAmplifierType.KEV_PRESENT, "vuln-1", Decimal("1.0"), _now()
    )
    assert amp.is_active
    amp2 = rec.attach_amplifier(
        tenant, RiskAmplifierType.KEV_PRESENT, "vuln-1", Decimal("1.0"), _now()
    )
    assert amp2.amplifier_id == amp.amplifier_id
    assert len(rec.active_amplifiers()) == 1


def test_suppress_requires_justification() -> None:
    rec = _record()
    with pytest.raises(SuppressionJustificationRequired):
        rec.suppress(rec.tenant_id, "  ", "analyst", _now())


def test_cannot_suppress_resolved() -> None:
    rec = _record()
    rec.resolve(rec.tenant_id, _now())
    with pytest.raises(InvalidExposureTransition):
        rec.suppress(rec.tenant_id, "ok", "analyst", _now())


def test_resolve_sets_immutable_resolved_at() -> None:
    rec = _record()
    rec.resolve(rec.tenant_id, _now())
    assert rec.status == ExposureStatus.RESOLVED
    assert rec.resolved_at is not None

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import uuid4

from exposure.domain.aggregates.amplifier_weight_configuration import (
    AmplifierWeightConfiguration,
)
from exposure.domain.aggregates.exposure_record import ExposureRecord
from exposure.domain.services.exposure_score_formula import (
    compute_asset_composite,
    compute_record_score,
    compute_tenant_exposure_score,
)
from exposure.domain.value_objects.enums import RiskAmplifierType, SignalDomain
from exposure.domain.value_objects.exposure_vos import AssetRef, ExposureLevel, SignalSourceRef
from exposure.domain.value_objects.identifiers import (
    AmplifierWeightConfigurationId,
    ExposureRecordId,
    TenantId,
)


def test_score_product_form_and_clamp() -> None:
    tenant = TenantId(uuid4())
    now = datetime(2026, 7, 21, tzinfo=UTC)
    cfg = AmplifierWeightConfiguration.create_default(
        AmplifierWeightConfigurationId.generate(), tenant, now
    )
    rec = ExposureRecord.create(
        ExposureRecordId.generate(),
        tenant,
        AssetRef(uuid4()),
        SignalDomain.VULNERABILITY_MANAGEMENT,
        SignalSourceRef("v1"),
        ExposureLevel(5.0),
        now,
    )
    rec.attach_amplifier(tenant, RiskAmplifierType.KEV_PRESENT, "v1", Decimal("1.0"), now)
    # 5.0 * (1+1.0) = 10.0
    assert compute_record_score(rec, cfg) == 10.0
    rec.attach_amplifier(tenant, RiskAmplifierType.DETECTION_GAP, "gap-1", Decimal("0.5"), now)
    # 5 * 2 * 1.5 = 15 → clamp 10
    assert compute_record_score(rec, cfg) == 10.0


def test_tenant_average() -> None:
    assert compute_tenant_exposure_score([2.0, 4.0, 6.0]) == 4.0
    assert compute_asset_composite([]) == 0.0

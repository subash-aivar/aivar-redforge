"""ORM <-> domain mapping helpers shared by both risk_engine
repositories (M48E).

Kept as pure functions in one module — following `credential_vault`'s
precedent of colocating `_to_domain`/`_from_domain` next to the
repository that owns the row — except here the `RiskSignalReference`
flattening is identical across `RiskProfileContributionModel` and
`RiskCorrelationSignalRefModel`, so that one mapping is factored out
to avoid duplicating it in both repository files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from risk_engine.domain.value_objects.enums import RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import TenantId
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference

if TYPE_CHECKING:
    from uuid import UUID

    from risk_engine.infrastructure.persistence.models.risk_correlation_model import (
        RiskCorrelationSignalRefModel,
    )
    from risk_engine.infrastructure.persistence.models.risk_profile_model import (
        RiskProfileContributionModel,
    )


def signal_reference_to_columns(signal: RiskSignalReference) -> dict[str, object]:
    """The flattened-column kwargs shared by both child-row ORM models."""
    return {
        "signal_tenant_id": signal.tenant_id.value.to_uuid(),
        "signal_source_context": signal.source_context,
        "signal_source_aggregate_type": signal.source_aggregate_type,
        "signal_source_id": signal.source_id,
        "signal_type": signal.signal_type.value,
        "signal_raw_value": signal.raw_value,
        "signal_raw_scale": signal.raw_scale.value,
        "signal_observed_at": signal.observed_at,
        "signal_subject_reference": signal.subject_reference,
    }


def row_to_signal_reference(
    row: RiskProfileContributionModel | RiskCorrelationSignalRefModel,
) -> RiskSignalReference:
    return RiskSignalReference(
        tenant_id=TenantId.from_uuid(row.signal_tenant_id),
        source_context=row.signal_source_context,
        source_aggregate_type=row.signal_source_aggregate_type,
        source_id=row.signal_source_id,
        signal_type=RiskSignalType(row.signal_type),
        raw_value=row.signal_raw_value,
        raw_scale=RiskScale(row.signal_raw_scale),
        observed_at=row.signal_observed_at,
        subject_reference=row.signal_subject_reference,
    )


def new_uuid() -> UUID:
    return uuid4()

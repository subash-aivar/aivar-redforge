"""Unit tests for the shared RiskSignalReference <-> column mappers —
no DB needed."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from risk_engine.domain.value_objects.enums import RiskScale, RiskSignalType
from risk_engine.infrastructure.persistence.mappers import (
    row_to_signal_reference,
    signal_reference_to_columns,
)
from tests.risk_engine.infrastructure.helpers import make_signal, make_tenant_id


@dataclass
class _FakeRow:
    signal_tenant_id: object
    signal_source_context: str
    signal_source_aggregate_type: str
    signal_source_id: str
    signal_type: str
    signal_raw_value: float
    signal_raw_scale: str
    signal_observed_at: datetime
    signal_subject_reference: str | None


def test_round_trip_preserves_all_fields() -> None:
    tenant_id = make_tenant_id()
    signal = make_signal(tenant_id, subject_reference="asset-7", source_id="src-1")

    columns = signal_reference_to_columns(signal)
    row = _FakeRow(
        signal_tenant_id=columns["signal_tenant_id"],
        signal_source_context=columns["signal_source_context"],
        signal_source_aggregate_type=columns["signal_source_aggregate_type"],
        signal_source_id=columns["signal_source_id"],
        signal_type=columns["signal_type"],
        signal_raw_value=columns["signal_raw_value"],
        signal_raw_scale=columns["signal_raw_scale"],
        signal_observed_at=columns["signal_observed_at"],
        signal_subject_reference=columns["signal_subject_reference"],
    )
    rebuilt = row_to_signal_reference(row)

    assert rebuilt.tenant_id == tenant_id
    assert rebuilt.source_context == signal.source_context
    assert rebuilt.source_aggregate_type == signal.source_aggregate_type
    assert rebuilt.source_id == "src-1"
    assert rebuilt.signal_type == RiskSignalType.SEVERITY_RATING
    assert rebuilt.raw_value == signal.raw_value
    assert rebuilt.raw_scale == RiskScale.CVSS_0_10
    assert rebuilt.observed_at == signal.observed_at
    assert rebuilt.subject_reference == "asset-7"


def test_none_subject_reference_round_trips_as_none() -> None:
    tenant_id = make_tenant_id()
    signal = make_signal(tenant_id, subject_reference=None)
    columns = signal_reference_to_columns(signal)
    assert columns["signal_subject_reference"] is None


def test_tenant_id_survives_uuid_bridge() -> None:
    tenant_id = make_tenant_id()
    signal = make_signal(tenant_id)
    columns = signal_reference_to_columns(signal)
    row = _FakeRow(
        signal_tenant_id=columns["signal_tenant_id"],
        signal_source_context=columns["signal_source_context"],
        signal_source_aggregate_type=columns["signal_source_aggregate_type"],
        signal_source_id=columns["signal_source_id"],
        signal_type=columns["signal_type"],
        signal_raw_value=columns["signal_raw_value"],
        signal_raw_scale=columns["signal_raw_scale"],
        signal_observed_at=columns["signal_observed_at"],
        signal_subject_reference=columns["signal_subject_reference"],
    )
    rebuilt = row_to_signal_reference(row)
    assert rebuilt.tenant_id == tenant_id
    assert str(rebuilt.tenant_id) == str(tenant_id)


def test_new_uuid_returns_unique_values() -> None:
    from risk_engine.infrastructure.persistence.mappers import new_uuid

    a, b = new_uuid(), new_uuid()
    assert a != b

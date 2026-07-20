"""TelemetrySource aggregate and value object tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.domain.events.telemetry_events import (
    TelemetrySourceDeactivated,
    TelemetrySourceHealthChanged,
    TelemetrySourceRegistered,
    TelemetrySourceSchemaUpdated,
)
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from detection.domain.value_objects.enums import (
    SourceHealthStatus,
    SourceLifecycleState,
    SourceTrustLevel,
    SourceType,
)
from detection.domain.value_objects.identifiers import TenantId
from detection.domain.value_objects.rule_logic import NormalizedFieldRef
from detection.domain.value_objects.telemetry import (
    ConnectionConfig,
    DataLatencyProfile,
    FieldDefinition,
    RetentionWindow,
    SourceSchema,
    TimeWindow,
)
from tests.detection.phase2_helpers import make_connection, make_schema, make_source


def test_register_emits_registered_event(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now)
    events = source.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], TelemetrySourceRegistered)
    assert source.lifecycle_state == SourceLifecycleState.ACTIVE
    assert source.health.status == SourceHealthStatus.UNKNOWN


def test_deactivate_and_reactivate(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    source.deactivate(tenant_id=tenant_id, reason="maintenance", now=now)
    assert source.lifecycle_state == SourceLifecycleState.DEACTIVATED
    events = source.pop_events()
    assert isinstance(events[0], TelemetrySourceDeactivated)
    source.reactivate(tenant_id=tenant_id, now=now)
    assert source.lifecycle_state == SourceLifecycleState.ACTIVE


def test_deactivate_requires_reason(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    with pytest.raises(InvalidArgument):
        source.deactivate(tenant_id=tenant_id, reason="  ", now=now)


def test_double_deactivate_blocked(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    source.deactivate(tenant_id=tenant_id, reason="done", now=now)
    with pytest.raises(InvalidStateTransition):
        source.deactivate(tenant_id=tenant_id, reason="again", now=now)


def test_health_change_emits_event(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    source.update_health(
        tenant_id=tenant_id,
        status=SourceHealthStatus.HEALTHY,
        now=now,
        success=True,
    )
    events = source.pop_events()
    assert isinstance(events[0], TelemetrySourceHealthChanged)
    assert source.health.status == SourceHealthStatus.HEALTHY
    assert source.health.consecutive_failures == 0


def test_health_failure_increments(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    source.update_health(
        tenant_id=tenant_id,
        status=SourceHealthStatus.DEGRADED,
        now=now,
        success=False,
        detail="timeout",
    )
    source.update_health(
        tenant_id=tenant_id,
        status=SourceHealthStatus.UNAVAILABLE,
        now=now,
        success=False,
        detail="timeout",
    )
    assert source.health.consecutive_failures == 2
    assert source.health.last_error == "timeout"


def test_schema_update_emits_event(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    new_schema = make_schema(version="1.1.0", paths=["event.event_type", "cloud.api_call"])
    source.update_schema(tenant_id=tenant_id, schema=new_schema, now=now)
    events = source.pop_events()
    assert isinstance(events[0], TelemetrySourceSchemaUpdated)
    assert source.schema.schema_version == "1.1.0"


def test_tenant_mismatch_on_mutate(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime
    from uuid import uuid4

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    other = TenantId(uuid4())
    with pytest.raises(TenantMismatch):
        source.deactivate(tenant_id=other, reason="x", now=now)


def test_connection_requires_tenant_scope() -> None:
    with pytest.raises(InvalidArgument):
        ConnectionConfig(adapter_key="x", tenant_scope_assertion="")


def test_source_schema_rejects_duplicate_fields() -> None:
    from detection.domain.value_objects.enums import FieldDataType

    with pytest.raises(InvalidArgument):
        SourceSchema(
            schema_version="1.0.0",
            fields=(
                FieldDefinition(
                    field_ref=NormalizedFieldRef("process.name"),
                    data_type=FieldDataType.STRING,
                ),
                FieldDefinition(
                    field_ref=NormalizedFieldRef("process.name"),
                    data_type=FieldDataType.STRING,
                ),
            ),
        )


def test_source_schema_requires_fields() -> None:
    with pytest.raises(InvalidArgument):
        SourceSchema(schema_version="1.0.0", fields=())


def test_latency_profile_validation() -> None:
    with pytest.raises(InvalidArgument):
        DataLatencyProfile(
            expected_latency=timedelta(seconds=10),
            max_acceptable_latency=timedelta(seconds=5),
        )


def test_retention_must_be_positive() -> None:
    with pytest.raises(InvalidArgument):
        RetentionWindow(retention=timedelta(seconds=0))


def test_time_window_end_after_start(now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    with pytest.raises(InvalidArgument):
        TimeWindow(start=now, end=now)


def test_register_rejects_empty_name(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    from detection.domain.aggregates.telemetry_source import TelemetrySource

    assert isinstance(now, datetime)
    with pytest.raises(InvalidArgument):
        TelemetrySource.register(
            tenant_id=tenant_id,
            name="  ",
            source_type=SourceType.CLOUD_TRAIL,
            trust_level=SourceTrustLevel.AUTHORITATIVE,
            schema=make_schema(),
            connection=make_connection(),
            latency_profile=DataLatencyProfile(expected_latency=timedelta(seconds=1)),
            retention=RetentionWindow(retention=timedelta(days=1)),
            now=now,
        )


@pytest.mark.parametrize(
    "source_type",
    list(SourceType),
)
def test_all_source_types_registerable(
    tenant_id: TenantId, now: object, source_type: SourceType
) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(
        tenant_id=tenant_id,
        now=now,
        name=f"src-{source_type.value}",
        source_type=source_type,
    )
    assert source.source_type == source_type


@pytest.mark.parametrize("trust", list(SourceTrustLevel))
def test_all_trust_levels(
    tenant_id: TenantId, now: object, trust: SourceTrustLevel
) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(
        tenant_id=tenant_id,
        now=now,
        name=f"trust-{trust.value}",
        trust_level=trust,
    )
    assert source.trust_level == trust


def test_is_active_property(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    assert source.is_active is True
    source.deactivate(tenant_id=tenant_id, reason="x", now=now)
    assert source.is_active is False


def test_update_metadata(tenant_id: TenantId, now: object) -> None:
    from datetime import datetime

    assert isinstance(now, datetime)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    source.update_metadata(
        tenant_id=tenant_id,
        now=now,
        description="updated",
        trust_level=SourceTrustLevel.AUTHORITATIVE,
    )
    assert source.description == "updated"
    assert source.trust_level == SourceTrustLevel.AUTHORITATIVE

"""Additional coverage for mappings helpers, DTOs, and edge cases."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.application.cloud_security.runtime.dtos import (
    IngestResultDTO,
    IngestRuntimeEventsCommand,
    RuntimeEventDTO,
    RuntimeSummaryDTO,
)
from redforge.application.cloud_security.runtime.normalization_service import (
    RuntimeNormalizationService,
)
from redforge.domain.cloud_security.runtime.entities import (
    RuntimeArtifact,
    RuntimeCorrelationReference,
    RuntimeEvidence,
    RuntimeMetadata,
)
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.exceptions import (
    RuntimeArtifactNotFoundError,
    RuntimeEventNotFoundError,
)
from redforge.domain.cloud_security.runtime.process import RuntimeNetworkConnection
from redforge.domain.cloud_security.runtime.value_objects import (
    CloudRuntimeEventId,
    RuntimeDirection,
    RuntimeEventType,
    RuntimeProtocol,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.runtime.adapters.aws_cloudtrail import (
    normalize_cloudtrail_record,
)
from redforge.infrastructure.cloud_security.runtime.adapters.azure_activity import (
    normalize_azure_activity,
)
from redforge.infrastructure.cloud_security.runtime.mappings import (
    connection_from_model,
    connection_to_model,
    event_from_model,
    event_to_model,
    process_from_model,
    process_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudRuntimeEventModel,
    RuntimeNetworkConnectionModel,
    RuntimeProcessModel,
)

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())
NOW = datetime(2026, 7, 19, 15, 0, tzinfo=UTC)
svc = RuntimeNormalizationService()


def _domain_event() -> CloudRuntimeEvent:
    return CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.CLOUDTRAIL,
        event_time=NOW,
        metadata=RuntimeMetadata(provider_event_id="map-1", event_name="ListUsers"),
        artifacts=[RuntimeArtifact(artifact_id="a", artifact_type="log", name="x")],
        evidence=[RuntimeEvidence(evidence_id="e", summary="s", details={"k": 1})],
        now=NOW,
    )


def test_event_model_round_trip() -> None:
    event = _domain_event()
    row = event_to_model(event)
    assert isinstance(row, CloudRuntimeEventModel)
    restored = event_from_model(row)
    assert restored.metadata.provider_event_id == "map-1"
    assert restored.artifacts[0].name == "x"


def test_process_model_round_trip() -> None:
    from redforge.domain.cloud_security.runtime.process import RuntimeProcess

    event = _domain_event()
    proc = RuntimeProcess.observe(
        organization_id=ORG,
        runtime_event_id=event.id,
        process_name="python",
        pid=1,
        now=NOW,
    )
    row = process_to_model(proc)
    assert isinstance(row, RuntimeProcessModel)
    restored = process_from_model(row)
    assert restored.process_name == "python"


def test_connection_model_round_trip() -> None:
    event = _domain_event()
    conn = RuntimeNetworkConnection.observe(
        organization_id=ORG,
        runtime_event_id=event.id,
        direction=RuntimeDirection.INBOUND,
        protocol=RuntimeProtocol.UDP,
        local_port=53,
        now=NOW,
    )
    row = connection_to_model(conn)
    assert isinstance(row, RuntimeNetworkConnectionModel)
    restored = connection_from_model(row)
    assert restored.protocol == RuntimeProtocol.UDP


def test_not_found_errors() -> None:
    with pytest.raises(RuntimeEventNotFoundError):
        raise RuntimeEventNotFoundError("missing")
    with pytest.raises(RuntimeArtifactNotFoundError):
        raise RuntimeArtifactNotFoundError("missing")


def test_dto_shapes() -> None:
    cmd = IngestRuntimeEventsCommand(
        organization_id=str(ORG),
        cloud_account_id=ACCOUNT.value,
        events=[{"event_id": "1", "event_name": "x", "event_time": NOW.isoformat()}],
    )
    assert len(cmd.events) == 1
    result = IngestResultDTO(
        organization_id=str(ORG),
        accepted=1,
        inserted=1,
        skipped_duplicates=0,
        event_ids=["a"],
    )
    assert result.inserted == 1
    summary = RuntimeSummaryDTO(
        organization_id=str(ORG),
        total_events=0,
        by_event_type={},
        by_source={},
        process_count=0,
        connection_count=0,
    )
    assert summary.total_events == 0
    dto = RuntimeEventDTO(
        event_id=str(uuid4()),
        organization_id=str(ORG),
        cloud_account_id=str(ACCOUNT),
        event_type="API_ACTIVITY",
        source="GENERIC",
        severity="INFO",
        outcome="UNKNOWN",
        event_time=NOW,
        ingested_at=NOW,
        event_name="x",
        provider_event_id="p",
        source_ip="",
        target_resource="",
        identity={},
        host={},
        container={},
        correlation_refs={},
    )
    assert dto.event_name == "x"


def test_cloud_runtime_event_id_helpers() -> None:
    eid = CloudRuntimeEventId.new()
    assert CloudRuntimeEventId.from_str(str(eid)).value == eid.value
    assert str(eid) == str(eid.value)


def test_correlation_reference_round_trip() -> None:
    ref = RuntimeCorrelationReference(
        target_kind="CloudAsset", target_id=str(uuid4()), relationship="observed_on"
    )
    assert RuntimeCorrelationReference.from_dict(ref.to_dict()) == ref


@pytest.mark.parametrize(
    "payload",
    [
        {"eventTime": datetime(2026, 7, 1, tzinfo=UTC), "eventName": "X", "eventID": "dt"},
        {"eventName": "Y", "eventID": "no-time"},
        {
            "eventID": "res",
            "eventTime": "2026-07-19T00:00:00Z",
            "eventName": "Z",
            "resources": [{"arn": "a"}],
            "userIdentity": "bad",
        },
    ],
)
def test_cloudtrail_normalize_variants(payload: dict) -> None:
    out = normalize_cloudtrail_record(payload)
    assert out["source"] == "CLOUDTRAIL"
    assert out["event_name"]


@pytest.mark.parametrize(
    "payload",
    [
        {
            "eventDataId": "1",
            "time": "2026-07-19T00:00:00Z",
            "operationName": "plain",
            "caller": {"principalId": "p1", "claims": {"name": "n"}},
        },
        {
            "id": "2",
            "eventTimestamp": datetime(2026, 7, 19, tzinfo=UTC),
            "operationName": {"value": "op"},
            "status": "Succeeded",
        },
    ],
)
def test_azure_normalize_variants(payload: dict) -> None:
    out = normalize_azure_activity(payload)
    assert out["source"] == "AZURE_ACTIVITY"


def test_normalize_generic_unknown() -> None:
    bundle = svc.normalize(
        {"event_id": "u1", "event_name": "weird", "event_time": "2026-07-19T00:00:00Z"},
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        source="GENERIC",
    )
    assert bundle.event.source == RuntimeSource.GENERIC


def test_source_ip_and_target_truncated() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=RuntimeMetadata(provider_event_id="t", event_name="n"),
        source_ip="x" * 200,
        target_resource="y" * 600,
        now=NOW,
    )
    assert len(event.source_ip) == 128
    assert len(event.target_resource) == 512

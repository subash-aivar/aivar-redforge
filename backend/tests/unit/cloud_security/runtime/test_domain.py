"""Domain unit tests for CloudRuntimeEvent and related aggregates."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.domain.cloud_security.runtime.entities import (
    RuntimeArtifact,
    RuntimeEvidence,
    RuntimeMetadata,
)
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent, _truncate_raw_payload
from redforge.domain.cloud_security.runtime.events import (
    RuntimeArtifactObserved,
    RuntimeEventIngested,
    RuntimeIdentityObserved,
)
from redforge.domain.cloud_security.runtime.exceptions import InvalidRuntimeArgumentError
from redforge.domain.cloud_security.runtime.process import (
    RuntimeFileActivity,
    RuntimeNetworkConnection,
    RuntimeProcess,
)
from redforge.domain.cloud_security.runtime.session import (
    RuntimeExecutionContext,
    RuntimeIdentitySession,
)
from redforge.domain.cloud_security.runtime.value_objects import (
    EventOutcome,
    RuntimeContainer,
    RuntimeCorrelationRefs,
    RuntimeDirection,
    RuntimeEventType,
    RuntimeHost,
    RuntimeIdentity,
    RuntimeProtocol,
    RuntimeSeverity,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())
NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


def _meta(event_id: str = "evt-1", name: str = "DescribeInstances") -> RuntimeMetadata:
    return RuntimeMetadata(provider_event_id=event_id, event_name=name, region="us-east-1")


def test_ingest_emits_runtime_event_ingested() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.CLOUDTRAIL,
        event_time=NOW,
        metadata=_meta(),
        now=NOW,
    )
    pending = event.pop_events()
    assert any(isinstance(e, RuntimeEventIngested) for e in pending)
    assert event.event_type == RuntimeEventType.API_ACTIVITY
    assert event.row_version == 1


def test_ingest_requires_provider_event_id() -> None:
    with pytest.raises(InvalidRuntimeArgumentError):
        CloudRuntimeEvent.ingest(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            event_type="API_ACTIVITY",
            source="CLOUDTRAIL",
            event_time=NOW,
            metadata=RuntimeMetadata(provider_event_id="", event_name="x"),
        )


def test_ingest_requires_event_name() -> None:
    with pytest.raises(InvalidRuntimeArgumentError):
        CloudRuntimeEvent.ingest(
            organization_id=ORG,
            cloud_account_id=ACCOUNT,
            event_type="API_ACTIVITY",
            source="CLOUDTRAIL",
            event_time=NOW,
            metadata=RuntimeMetadata(provider_event_id="id", event_name=""),
        )


def test_ingest_emits_identity_observed() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.IDENTITY_SESSION,
        source=RuntimeSource.AZURE_ACTIVITY,
        event_time=NOW,
        metadata=_meta("login-1", "ConsoleLogin"),
        identity=RuntimeIdentity(principal_id="user-1", principal_type="User"),
        now=NOW,
    )
    pending = event.pop_events()
    assert any(isinstance(e, RuntimeIdentityObserved) for e in pending)


def test_ingest_emits_artifact_observed() -> None:
    art = RuntimeArtifact(artifact_id="a1", artifact_type="file", name="bin")
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.FILE_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("file-1", "WriteFile"),
        artifacts=[art],
        now=NOW,
    )
    pending = event.pop_events()
    assert any(isinstance(e, RuntimeArtifactObserved) for e in pending)


def test_truncate_raw_payload_under_limit() -> None:
    payload = {"a": 1, "b": "ok"}
    assert _truncate_raw_payload(payload) == payload


def test_truncate_raw_payload_over_64kb() -> None:
    huge = {"blob": "x" * (70 * 1024)}
    truncated = _truncate_raw_payload(huge)
    assert truncated["_truncated"] is True
    assert truncated["_original_bytes"] > 64 * 1024


def test_ingest_truncates_large_raw_payload() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta(),
        raw_payload={"blob": "y" * (70 * 1024)},
        now=NOW,
    )
    assert event.raw_payload.get("_truncated") is True


def test_cspm_snapshot_shape() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.CLOUDTRAIL,
        event_time=NOW,
        metadata=_meta(),
        identity=RuntimeIdentity(principal_id="p1", principal_type="AssumedRole"),
        source_ip="1.2.3.4",
        target_resource="arn:aws:ec2:...",
        now=NOW,
    )
    snap = event.cspm_snapshot()
    assert snap["asset_type"] == "RUNTIME_EVENT"
    assert snap["normalized_config"]["principal_id"] == "p1"
    assert snap["source_ip"] == "1.2.3.4"
    assert "identity" in snap
    assert "host" in snap
    assert "container" in snap


def test_bind_correlation_refs_bumps_version() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta(),
        now=NOW,
    )
    asset_id = uuid4()
    event.bind_correlation_refs(
        RuntimeCorrelationRefs(
            cloud_asset_id=asset_id,
            cloud_account_id=ACCOUNT.value,
            organization_id=str(ORG),
        )
    )
    assert event.correlation_refs.cloud_asset_id == asset_id
    assert event.row_version == 2


def test_process_observe() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.PROCESS_EXECUTION,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("proc-1", "exec"),
        now=NOW,
    )
    proc = RuntimeProcess.observe(
        organization_id=ORG,
        runtime_event_id=event.id,
        process_name="bash",
        executable_path="/bin/bash",
        pid=42,
        now=NOW,
    )
    assert proc.process_name == "bash"
    assert proc.pop_events()


def test_process_requires_name() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.PROCESS_EXECUTION,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("proc-2", "exec"),
        now=NOW,
    )
    with pytest.raises(InvalidRuntimeArgumentError):
        RuntimeProcess.observe(
            organization_id=ORG, runtime_event_id=event.id, process_name="  "
        )


def test_network_connection_observe() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.NETWORK_CONNECTION,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("net-1", "connect"),
        now=NOW,
    )
    conn = RuntimeNetworkConnection.observe(
        organization_id=ORG,
        runtime_event_id=event.id,
        direction=RuntimeDirection.OUTBOUND,
        protocol=RuntimeProtocol.TCP,
        remote_address="8.8.8.8",
        remote_port=53,
        now=NOW,
    )
    assert conn.direction == RuntimeDirection.OUTBOUND
    assert conn.pop_events()


def test_file_activity_observe() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.FILE_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("file-2", "write"),
        now=NOW,
    )
    activity = RuntimeFileActivity.observe(
        organization_id=ORG,
        runtime_event_id=event.id,
        operation="write",
        path="/tmp/x",
        file_hash="abc",
        now=NOW,
    )
    assert activity.path == "/tmp/x"


def test_file_activity_requires_path() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.FILE_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("file-3", "write"),
        now=NOW,
    )
    with pytest.raises(InvalidRuntimeArgumentError):
        RuntimeFileActivity.observe(
            organization_id=ORG,
            runtime_event_id=event.id,
            operation="write",
            path="",
        )


def test_identity_session_observe() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.IDENTITY_SESSION,
        source=RuntimeSource.GCP_AUDIT,
        event_time=NOW,
        metadata=_meta("sess-1", "login"),
        now=NOW,
    )
    session = RuntimeIdentitySession.observe(
        organization_id=ORG,
        runtime_event_id=event.id,
        identity=RuntimeIdentity(principal_id="u1", principal_name="u1"),
        mfa_used=True,
        now=NOW,
    )
    assert session.mfa_used is True


def test_identity_session_requires_principal() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.IDENTITY_SESSION,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta("sess-2", "login"),
        now=NOW,
    )
    with pytest.raises(InvalidRuntimeArgumentError):
        RuntimeIdentitySession.observe(
            organization_id=ORG,
            runtime_event_id=event.id,
            identity=RuntimeIdentity(),
        )


def test_execution_context_create() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.CONTAINER_EXECUTION,
        source=RuntimeSource.KUBERNETES_AUDIT,
        event_time=NOW,
        metadata=_meta("ctx-1", "exec"),
        container=RuntimeContainer(container_id="c1", pod_name="web"),
        host=RuntimeHost(host_id="h1"),
        now=NOW,
    )
    ctx = RuntimeExecutionContext.create(
        organization_id=ORG,
        runtime_event_id=event.id,
        container_id="c1",
        host_id="h1",
        workload_ref="web",
        now=NOW,
    )
    assert ctx.workload_ref == "web"


@pytest.mark.parametrize(
    "etype",
    list(RuntimeEventType),
)
def test_all_event_types_ingestable(etype: RuntimeEventType) -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=etype,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta(f"id-{etype.value}", etype.value),
        now=NOW,
    )
    assert event.event_type == etype


@pytest.mark.parametrize("source", list(RuntimeSource))
def test_all_sources_ingestable(source: RuntimeSource) -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=source,
        event_time=NOW,
        metadata=_meta(f"id-{source.value}", "evt"),
        now=NOW,
    )
    assert event.source == source


@pytest.mark.parametrize("severity", list(RuntimeSeverity))
def test_all_severities(severity: RuntimeSeverity) -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta(f"sev-{severity.value}", "evt"),
        severity=severity,
        now=NOW,
    )
    assert event.severity == severity


@pytest.mark.parametrize("outcome", list(EventOutcome))
def test_all_outcomes(outcome: EventOutcome) -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.GENERIC,
        event_time=NOW,
        metadata=_meta(f"out-{outcome.value}", "evt"),
        outcome=outcome,
        now=NOW,
    )
    assert event.outcome == outcome


def test_value_object_round_trips() -> None:
    ident = RuntimeIdentity(principal_id="p", principal_type="User", principal_name="n")
    assert RuntimeIdentity.from_dict(ident.to_dict()) == ident
    host = RuntimeHost(hostname="h", host_id="id", region="r")
    assert RuntimeHost.from_dict(host.to_dict()) == host
    container = RuntimeContainer(container_id="c", image="img", namespace="ns")
    assert RuntimeContainer.from_dict(container.to_dict()) == container
    refs = RuntimeCorrelationRefs(
        cloud_asset_id=uuid4(),
        cloud_account_id=uuid4(),
        organization_id="org",
    )
    assert RuntimeCorrelationRefs.from_dict(refs.to_dict()).organization_id == "org"
    meta = RuntimeMetadata(provider_event_id="e", event_name="n", attributes=(("a", "b"),))
    assert RuntimeMetadata.from_dict(meta.to_dict()).event_name == "n"
    art = RuntimeArtifact(artifact_id="a", artifact_type="t", name="n")
    assert RuntimeArtifact.from_dict(art.to_dict()).name == "n"
    ev = RuntimeEvidence(evidence_id="e", summary="s", details={"k": 1})
    assert RuntimeEvidence.from_dict(ev.to_dict()).summary == "s"


def test_string_enums_accepted_on_ingest() -> None:
    event = CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type="api_activity",
        source="cloudtrail",
        event_time=NOW,
        metadata=_meta("str-enum", "x"),
        outcome="success",
        severity="high",
        now=NOW,
    )
    assert event.event_type == RuntimeEventType.API_ACTIVITY
    assert event.source == RuntimeSource.CLOUDTRAIL
    assert event.outcome == EventOutcome.SUCCESS
    assert event.severity == RuntimeSeverity.HIGH

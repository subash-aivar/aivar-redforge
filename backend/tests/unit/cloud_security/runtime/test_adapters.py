"""Unit tests for runtime source adapters (raw dict only)."""

from __future__ import annotations

import pytest

from redforge.domain.cloud_security.ports import RawRuntimeEvent
from redforge.infrastructure.cloud_security.runtime.adapters.aws_cloudtrail import (
    AwsCloudTrailAdapter,
    normalize_cloudtrail_record,
)
from redforge.infrastructure.cloud_security.runtime.adapters.azure_activity import (
    AzureActivityAdapter,
    normalize_azure_activity,
)
from redforge.infrastructure.cloud_security.runtime.adapters.gcp_audit import (
    GcpAuditAdapter,
    normalize_gcp_audit,
)
from redforge.infrastructure.cloud_security.runtime.adapters.kubernetes_audit import (
    KubernetesAuditAdapter,
    normalize_kubernetes_audit,
)
from redforge.infrastructure.cloud_security.runtime.fake_adapter import FakeRuntimeSourceAdapter


def test_normalize_cloudtrail_basic() -> None:
    out = normalize_cloudtrail_record(
        {
            "eventID": "e1",
            "eventTime": "2026-07-19T00:00:00Z",
            "eventName": "GetCallerIdentity",
            "userIdentity": {"type": "IAMUser", "userName": "alice", "accountId": "1"},
            "sourceIPAddress": "1.1.1.1",
        }
    )
    assert out["source"] == "CLOUDTRAIL"
    assert out["event_id"] == "e1"
    assert out["identity"]["principal_name"] == "alice"


@pytest.mark.asyncio
async def test_aws_adapter_records_envelope() -> None:
    adapter = AwsCloudTrailAdapter(
        [
            {
                "Records": [
                    {
                        "eventID": "r1",
                        "eventTime": "2026-07-19T00:00:00Z",
                        "eventName": "ListBuckets",
                        "userIdentity": {"type": "Root", "accountId": "1"},
                    },
                    {
                        "eventID": "r2",
                        "eventTime": "2026-07-19T00:01:00Z",
                        "eventName": "ListBuckets",
                        "userIdentity": {"type": "Root", "accountId": "1"},
                    },
                ]
            }
        ]
    )
    events = [e async for e in adapter.stream_events()]
    assert len(events) == 2
    assert all(isinstance(e, RawRuntimeEvent) for e in events)
    assert events[0].source == "CLOUDTRAIL"


@pytest.mark.asyncio
async def test_aws_adapter_seed_and_clear() -> None:
    adapter = AwsCloudTrailAdapter()
    adapter.seed(
        {
            "eventID": "s1",
            "eventTime": "2026-07-19T00:00:00Z",
            "eventName": "X",
            "userIdentity": {},
        }
    )
    assert len([e async for e in adapter.stream_events()]) == 1
    adapter.clear()
    assert [e async for e in adapter.stream_events()] == []


def test_normalize_azure_activity_basic() -> None:
    out = normalize_azure_activity(
        {
            "eventDataId": "az",
            "eventTimestamp": "2026-07-19T00:00:00Z",
            "operationName": {"value": "Microsoft.Storage/write"},
            "caller": "a@b.com",
            "status": {"value": "Succeeded"},
        }
    )
    assert out["source"] == "AZURE_ACTIVITY"
    assert out["event_name"] == "Microsoft.Storage/write"


@pytest.mark.asyncio
async def test_azure_adapter_value_list() -> None:
    adapter = AzureActivityAdapter(
        [
            {
                "value": [
                    {
                        "eventDataId": "a1",
                        "eventTimestamp": "2026-07-19T00:00:00Z",
                        "operationName": {"value": "op"},
                        "caller": "x",
                    }
                ]
            }
        ]
    )
    events = [e async for e in adapter.stream_events()]
    assert len(events) == 1
    assert events[0].source == "AZURE_ACTIVITY"


def test_normalize_gcp_audit_basic() -> None:
    out = normalize_gcp_audit(
        {
            "insertId": "g1",
            "timestamp": "2026-07-19T00:00:00Z",
            "protoPayload": {
                "methodName": "compute.instances.insert",
                "authenticationInfo": {"principalEmail": "u@proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "2.2.2.2"},
            },
        }
    )
    assert out["source"] == "GCP_AUDIT"
    assert out["identity"]["principal_type"] == "serviceAccount"


@pytest.mark.asyncio
async def test_gcp_adapter_entries() -> None:
    adapter = GcpAuditAdapter(
        [
            {
                "entries": [
                    {
                        "insertId": "e1",
                        "timestamp": "2026-07-19T00:00:00Z",
                        "protoPayload": {
                            "methodName": "m",
                            "authenticationInfo": {"principalEmail": "u@x.com"},
                        },
                    }
                ]
            }
        ]
    )
    events = [e async for e in adapter.stream_events()]
    assert len(events) == 1


def test_normalize_k8s_audit_basic() -> None:
    out = normalize_kubernetes_audit(
        {
            "auditID": "k1",
            "verb": "get",
            "requestReceivedTimestamp": "2026-07-19T00:00:00Z",
            "user": {"username": "admin", "uid": "1"},
            "objectRef": {"resource": "secrets", "name": "s", "namespace": "ns"},
            "sourceIPs": ["10.0.0.1"],
        }
    )
    assert out["source"] == "KUBERNETES_AUDIT"
    assert out["event_name"] == "get:secrets"
    assert out["container"]["namespace"] == "ns"


@pytest.mark.asyncio
async def test_k8s_adapter_items() -> None:
    adapter = KubernetesAuditAdapter(
        [
            {
                "items": [
                    {
                        "auditID": "i1",
                        "verb": "list",
                        "requestReceivedTimestamp": "2026-07-19T00:00:00Z",
                        "user": {"username": "u"},
                        "objectRef": {"resource": "pods", "namespace": "default"},
                    }
                ]
            }
        ]
    )
    events = [e async for e in adapter.stream_events()]
    assert len(events) == 1
    assert events[0].source == "KUBERNETES_AUDIT"


@pytest.mark.asyncio
async def test_fake_adapter_sample_and_stream() -> None:
    fake = FakeRuntimeSourceAdapter()
    sample = FakeRuntimeSourceAdapter.sample_event(event_name="Sample")
    fake.seed(sample)
    fake.seed_many([FakeRuntimeSourceAdapter.sample_event(event_id="x2")])
    events = [e async for e in fake.stream_events()]
    assert len(events) == 2
    fake.clear()
    assert [e async for e in fake.stream_events()] == []


@pytest.mark.parametrize(
    "factory",
    [AwsCloudTrailAdapter, AzureActivityAdapter, GcpAuditAdapter, KubernetesAuditAdapter],
)
def test_adapters_clear(factory: type) -> None:
    adapter = factory()
    adapter.clear()
    assert adapter._payloads == []

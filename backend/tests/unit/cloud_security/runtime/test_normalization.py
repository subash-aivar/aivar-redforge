"""Normalization service tests for AWS/Azure/GCP/K8s sample payloads."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.application.cloud_security.runtime.normalization_service import (
    RuntimeNormalizationService,
)
from redforge.domain.cloud_security.ports import RawRuntimeEvent
from redforge.domain.cloud_security.runtime.value_objects import RuntimeEventType, RuntimeSource
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())
svc = RuntimeNormalizationService()


def test_normalize_cloudtrail_console_login() -> None:
    raw = {
        "eventID": "ct-1",
        "eventTime": "2026-07-19T10:00:00Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.1",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA...",
            "userName": "alice",
            "accountId": "111122223333",
        },
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.source == RuntimeSource.CLOUDTRAIL
    assert bundle.event.event_type == RuntimeEventType.IDENTITY_SESSION
    assert bundle.event.identity.principal_name == "alice"
    assert bundle.identity_session is not None


def test_normalize_cloudtrail_api_activity() -> None:
    raw = {
        "eventID": "ct-2",
        "eventTime": "2026-07-19T11:00:00Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "awsRegion": "eu-west-1",
        "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/r/s"},
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.event_type == RuntimeEventType.API_ACTIVITY
    assert bundle.event.metadata.region == "eu-west-1"


def test_normalize_azure_activity() -> None:
    raw = {
        "eventDataId": "az-1",
        "eventTimestamp": "2026-07-19T09:00:00Z",
        "operationName": {"value": "Microsoft.Compute/virtualMachines/start/action"},
        "status": {"value": "Succeeded"},
        "caller": "bob@contoso.com",
        "subscriptionId": "sub-1",
        "resourceId": "/subscriptions/sub-1/vm/1",
        "httpRequest": {"clientIpAddress": "10.1.1.1"},
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.source == RuntimeSource.AZURE_ACTIVITY
    assert bundle.event.outcome.value == "SUCCESS"
    assert bundle.event.target_resource


def test_normalize_gcp_audit() -> None:
    raw = {
        "insertId": "gcp-1",
        "timestamp": "2026-07-19T08:00:00Z",
        "severity": "NOTICE",
        "protoPayload": {
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "authenticationInfo": {"principalEmail": "sa@proj.iam.gserviceaccount.com"},
            "requestMetadata": {"callerIp": "9.9.9.9"},
            "resourceName": "projects/proj/serviceAccounts/sa",
        },
        "resource": {"labels": {"project_id": "proj", "location": "us-central1"}},
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.source == RuntimeSource.GCP_AUDIT
    assert "serviceAccount" in bundle.event.identity.principal_type or bundle.event.identity.principal_id


def test_normalize_kubernetes_audit_exec() -> None:
    raw = {
        "auditID": "k8s-1",
        "verb": "create",
        "requestReceivedTimestamp": "2026-07-19T07:00:00Z",
        "user": {"username": "system:serviceaccount:default:runner", "uid": "u1"},
        "objectRef": {"resource": "pods", "name": "web", "namespace": "default"},
        "sourceIPs": ["10.0.0.5"],
        "responseStatus": {"code": 201},
    }
    # Force exec naming for container execution inference
    raw["verb"] = "create"
    raw["objectRef"]["subresource"] = "exec"
    # event_name becomes create:pods — add exec via method override after normalize path
    bundle = svc.normalize(
        {**raw, "event_name": "create:pods/exec"},
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        source="KUBERNETES_AUDIT",
    )
    assert bundle.event.source == RuntimeSource.KUBERNETES_AUDIT


def test_normalize_raw_runtime_event_wrapper() -> None:
    wrapped = RawRuntimeEvent(
        event_id="wrap-1",
        event_time=datetime(2026, 7, 19, tzinfo=UTC),
        source="GENERIC",
        payload={
            "event_id": "wrap-1",
            "event_name": "Ping",
            "event_time": "2026-07-19T00:00:00Z",
            "identity": {"principal_id": "p"},
        },
    )
    bundle = svc.normalize(wrapped, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.metadata.provider_event_id == "wrap-1"


def test_normalize_process_bundle() -> None:
    raw = {
        "event_id": "proc-n",
        "event_name": "process_exec",
        "event_time": "2026-07-19T01:00:00Z",
        "source": "GENERIC",
        "process": {
            "process_name": "curl",
            "executable_path": "/usr/bin/curl",
            "pid": 9,
            "command_line": "curl https://x",
        },
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.process is not None
    assert bundle.process.process_name == "curl"
    assert bundle.execution_context is not None


def test_normalize_network_bundle() -> None:
    raw = {
        "event_id": "net-n",
        "event_name": "network_connect",
        "event_time": "2026-07-19T02:00:00Z",
        "source": "GENERIC",
        "network": {
            "direction": "OUTBOUND",
            "protocol": "TCP",
            "remote_address": "1.1.1.1",
            "remote_port": 443,
        },
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.connection is not None
    assert bundle.connection.remote_port == 443


def test_normalize_file_bundle() -> None:
    raw = {
        "event_id": "file-n",
        "event_name": "file_write",
        "event_time": "2026-07-19T03:00:00Z",
        "source": "GENERIC",
        "file": {"operation": "write", "path": "/etc/passwd", "file_hash": "deadbeef"},
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.file_activity is not None


def test_normalize_many() -> None:
    events = [
        {
            "event_id": f"m-{i}",
            "event_name": "DescribeInstances",
            "event_time": "2026-07-19T04:00:00Z",
            "source": "CLOUDTRAIL",
            "identity": {"principal_id": f"p{i}"},
        }
        for i in range(5)
    ]
    bundles = svc.normalize_many(events, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert len(bundles) == 5


def test_normalize_failure_outcome_from_error_code() -> None:
    raw = {
        "eventID": "ct-fail",
        "eventTime": "2026-07-19T05:00:00Z",
        "eventName": "AssumeRole",
        "errorCode": "AccessDenied",
        "userIdentity": {"type": "IAMUser", "userName": "x"},
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.outcome.value == "FAILURE"


@pytest.mark.parametrize(
    "event_name,expected",
    [
        ("ConsoleLogin", RuntimeEventType.IDENTITY_SESSION),
        ("network_connect", RuntimeEventType.NETWORK_CONNECTION),
        ("PutObject", RuntimeEventType.FILE_ACTIVITY),
        ("StartInstances", RuntimeEventType.PROCESS_EXECUTION),
        ("DescribeInstances", RuntimeEventType.API_ACTIVITY),
    ],
)
def test_event_type_inference(event_name: str, expected: RuntimeEventType) -> None:
    raw = {
        "event_id": f"inf-{event_name}",
        "event_name": event_name,
        "event_time": "2026-07-19T06:00:00Z",
        "source": "CLOUDTRAIL",
        "identity": {"principal_id": "p"},
    }
    bundle = svc.normalize(raw, organization_id=ORG, cloud_account_id=ACCOUNT)
    assert bundle.event.event_type == expected

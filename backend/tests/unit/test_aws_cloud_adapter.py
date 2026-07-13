"""Contract-level tests for the read-only AWS discovery adapter — M7.

Uses `botocore.stub.Stubber` — a real SDK testing feature that
intercepts calls at the botocore client layer and returns canned,
schema-validated responses — to exercise the REAL boto3/botocore
client code paths (pagination, response parsing, error handling)
without a network connection or real AWS credentials. This proves the
adapter's SDK integration is CONTRACT-PROVEN, not that a live AWS
account was discovered — live AWS account discovery is separately and
honestly reported BLOCKED in the M7 report (no AWS credentials are
configured in this environment).
"""

from __future__ import annotations

import boto3
import pytest
from botocore.stub import ANY, Stubber

from redforge.application.cloud_security.aws_adapter import (
    AwsCloudAdapter,
    AwsCredential,
    AwsDiscoveryError,
)
from redforge.application.cloud_security.observations import CloudResourceClass

_CRED = AwsCredential(access_key_id="AKIASENTINELTEST0000", secret_access_key="sentinel-secret-value")


def _stubbed_session():
    session = boto3.Session(
        aws_access_key_id=_CRED.access_key_id,
        aws_secret_access_key=_CRED.secret_access_key,
        region_name="us-east-1",
    )
    return session


@pytest.fixture
def patched_boto3(monkeypatch: pytest.MonkeyPatch):
    """Patches `boto3.Session` (as imported inside the adapter) to
    return one shared session whose clients we stub per-service."""
    session = _stubbed_session()
    clients: dict[str, object] = {}
    stubbers: dict[str, Stubber] = {}

    original_client = session.client

    def _client(service_name: str, **kwargs: object) -> object:
        if service_name not in clients:
            c = original_client(service_name, **kwargs)
            clients[service_name] = c
            stubbers[service_name] = Stubber(c)
        return clients[service_name]

    session.client = _client  # type: ignore[method-assign]
    for service_name in ("sts", "ec2", "s3"):
        _client(service_name)

    import redforge.application.cloud_security.aws_adapter as adapter_module

    monkeypatch.setattr(adapter_module.boto3, "Session", lambda **kw: session)
    return session, stubbers


def test_discover_account_and_resources(patched_boto3) -> None:
    _session, stubbers = patched_boto3
    stubbers["sts"].add_response("get_caller_identity", {"Account": "123456789012", "UserId": "AIDASENTINEL000000", "Arn": "arn:aws:iam::123456789012:user/sentinel"})
    stubbers["ec2"].add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "OwnerId": "123456789012",
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "InstanceType": "t3.micro",
                            "PublicIpAddress": "203.0.113.5",
                            "Tags": [{"Key": "Name", "Value": "web-server"}],
                        }
                    ]
                }
            ]
        },
        {"Filters": ANY} if False else {},
    )
    stubbers["s3"].add_response("list_buckets", {"Buckets": [{"Name": "my-bucket"}]})
    stubbers["s3"].add_response(
        "get_bucket_acl",
        {
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ]
        },
        {"Bucket": "my-bucket"},
    )

    for s in stubbers.values():
        s.activate()

    result = AwsCloudAdapter().discover(_CRED, "us-east-1")

    assert result.account.account_identifier == "123456789012"
    assert len(result.resources) == 2
    ec2_resource = next(r for r in result.resources if r.resource_class == CloudResourceClass.COMPUTE)
    assert ec2_resource.public is True
    assert ec2_resource.display_name == "web-server"
    assert ec2_resource.native_resource_id == "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0"

    s3_resource = next(r for r in result.resources if r.resource_class == CloudResourceClass.STORAGE)
    assert s3_resource.public is True
    assert s3_resource.native_resource_id == "arn:aws:s3:::my-bucket"

    for s in stubbers.values():
        s.assert_no_pending_responses()


def test_private_resources_not_flagged_public(patched_boto3) -> None:
    _session, stubbers = patched_boto3
    stubbers["sts"].add_response("get_caller_identity", {"Account": "999999999999", "UserId": "AIDASENTINEL000000", "Arn": "arn:aws:iam::123456789012:user/sentinel"})
    stubbers["ec2"].add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "OwnerId": "999999999999",
                    "Instances": [
                        {
                            "InstanceId": "i-0999",
                            "InstanceType": "t3.micro",
                        }
                    ]
                }
            ]
        },
    )
    stubbers["s3"].add_response("list_buckets", {"Buckets": [{"Name": "private-bucket"}]})
    stubbers["s3"].add_response(
        "get_bucket_acl",
        {"Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"}]},
        {"Bucket": "private-bucket"},
    )
    for s in stubbers.values():
        s.activate()

    result = AwsCloudAdapter().discover(_CRED, "us-east-1")
    assert all(not r.public for r in result.resources)


def test_sts_failure_raises_sanitized_error_no_credential_leak(patched_boto3) -> None:
    _session, stubbers = patched_boto3
    stubbers["sts"].add_client_error("get_caller_identity", service_error_code="AccessDenied")
    stubbers["sts"].activate()

    with pytest.raises(AwsDiscoveryError) as exc_info:
        AwsCloudAdapter().discover(_CRED, "us-east-1")

    assert _CRED.secret_access_key not in str(exc_info.value)
    assert _CRED.access_key_id not in str(exc_info.value)
    assert "AccessDenied" in str(exc_info.value)


def test_ec2_failure_recorded_as_error_not_raised(patched_boto3) -> None:
    _session, stubbers = patched_boto3
    stubbers["sts"].add_response("get_caller_identity", {"Account": "123456789012", "UserId": "AIDASENTINEL000000", "Arn": "arn:aws:iam::123456789012:user/sentinel"})
    stubbers["ec2"].add_client_error("describe_instances", service_error_code="UnauthorizedOperation")
    stubbers["s3"].add_response("list_buckets", {"Buckets": []})
    for s in stubbers.values():
        s.activate()

    result = AwsCloudAdapter().discover(_CRED, "us-east-1")
    assert any("EC2 discovery failed" in e for e in result.errors)
    assert not any(r.resource_class == CloudResourceClass.COMPUTE for r in result.resources)


def test_no_mutation_methods_exposed() -> None:
    """Capability boundary: no method on the adapter accepts a service
    name/operation/params tuple, nor exposes create/delete/modify."""
    public_methods = {m for m in dir(AwsCloudAdapter) if not m.startswith("_")}
    assert public_methods == {"discover"}

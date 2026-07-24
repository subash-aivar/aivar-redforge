from __future__ import annotations

import pytest

from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidAzureResourceIdError,
    InvalidCloudArnError,
    InvalidGcpResourceNameError,
)
from cloud_security.domain.value_objects.native_resource_identifiers import (
    AzureResourceId,
    CloudArn,
    GcpResourceName,
)


def test_cloud_arn_requires_arn_prefix() -> None:
    CloudArn("arn:aws:s3:::my-bucket")
    with pytest.raises(InvalidCloudArnError):
        CloudArn("not-an-arn")


def test_azure_resource_id_requires_subscriptions_prefix() -> None:
    AzureResourceId("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/x")
    with pytest.raises(InvalidAzureResourceIdError):
        AzureResourceId("not-an-azure-id")


def test_gcp_resource_name_requires_projects_prefix() -> None:
    GcpResourceName("projects/my-project/zones/us-central1-a/instances/vm-1")
    with pytest.raises(InvalidGcpResourceNameError):
        GcpResourceName("not-a-gcp-name")

"""Unit tests for M26 Phase 2 CloudAsset domain and normalizers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.domain.cloud_security.cloud_asset import CloudAsset, relationship
from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.events import (
    CloudAssetDeleted,
    CloudAssetDiscovered,
    CloudAssetUpdated,
)
from redforge.domain.cloud_security.exceptions import (
    CloudAssetDeletedError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.ports import RawAsset
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetRelationshipType,
    CloudAssetType,
    NetworkExposure,
    NormalizedConfig,
    OrganizationId,
    ProviderMetadata,
)
from redforge.infrastructure.cloud_security.adapters.aws import (
    AWSCloudProviderAdapter,
    StaticAwsDiscoveryClient,
)
from redforge.infrastructure.cloud_security.adapters.azure import (
    AzureCloudProviderAdapter,
    StaticAzureDiscoveryClient,
)
from redforge.infrastructure.cloud_security.adapters.gcp import (
    GCPCloudProviderAdapter,
    StaticGcpDiscoveryClient,
)
from redforge.infrastructure.cloud_security.normalizers import normalize_raw_asset


def _config(**kwargs: object) -> NormalizedConfig:
    base = {
        "schema_version": "1",
        "resource_class": "compute",
        "network_exposure": NetworkExposure.PRIVATE,
    }
    base.update(kwargs)
    return NormalizedConfig(
        schema_version=str(base["schema_version"]),
        resource_class=str(base["resource_class"]),
        network_exposure=base["network_exposure"]  # type: ignore[arg-type]
        if isinstance(base["network_exposure"], NetworkExposure)
        else NetworkExposure(str(base["network_exposure"])),
        vpc_id=str(base["vpc_id"]) if base.get("vpc_id") else None,
        security_group_ids=tuple(base.get("security_group_ids") or ()),  # type: ignore[arg-type]
        kms_key_id=str(base["kms_key_id"]) if base.get("kms_key_id") else None,
        iam_role_arn=str(base["iam_role_arn"]) if base.get("iam_role_arn") else None,
    )


def test_cloud_asset_discover_emits_event() -> None:
    asset = CloudAsset.discover(
        cloud_account_id=CloudAccountId.generate(),
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        asset_type=CloudAssetType.EC2_INSTANCE,
        provider_id="arn:aws:ec2:us-east-1:123:instance/i-1",
        region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
        display_name="web-1",
        provider_metadata=ProviderMetadata.empty(),
        normalized_config=_config(vpc_id="vpc-1"),
        relationships=[
            relationship(
                relationship_type=CloudAssetRelationshipType.CONTAINED_IN,
                target_provider_id="vpc-1",
            )
        ],
        now=datetime.now(UTC),
    )
    events = asset.pop_events()
    assert any(isinstance(e, CloudAssetDiscovered) for e in events)
    assert len(asset.relationships) == 1


def test_deleted_asset_cannot_be_updated() -> None:
    asset = CloudAsset.discover(
        cloud_account_id=CloudAccountId.generate(),
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        asset_type=CloudAssetType.S3_BUCKET,
        provider_id="arn:aws:s3:::bucket",
        region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
        display_name="bucket",
        provider_metadata=ProviderMetadata.empty(),
        normalized_config=_config(resource_class="storage"),
    )
    asset.pop_events()
    asset.mark_deleted()
    assert isinstance(asset.pop_events()[0], CloudAssetDeleted)
    with pytest.raises(CloudAssetDeletedError):
        asset.apply_discovery(
            display_name="bucket",
            provider_metadata=ProviderMetadata.empty(),
            normalized_config=_config(resource_class="storage"),
            tags={},
            region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
            availability_zone=None,
            relationships=[],
        )


def test_resurrect_after_soft_delete() -> None:
    asset = CloudAsset.discover(
        cloud_account_id=CloudAccountId.generate(),
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        asset_type=CloudAssetType.VPC,
        provider_id="vpc-abc",
        region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
        display_name="vpc",
        provider_metadata=ProviderMetadata.empty(),
        normalized_config=_config(resource_class="network"),
    )
    asset.pop_events()
    asset.mark_deleted()
    asset.pop_events()
    asset.resurrect_from_discovery(
        display_name="vpc-restored",
        provider_metadata=ProviderMetadata.empty(),
        normalized_config=_config(resource_class="network"),
        tags={"env": "prod"},
        region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
        availability_zone=None,
        relationships=[],
    )
    assert asset.is_deleted is False
    assert asset.display_name == "vpc-restored"
    events = asset.pop_events()
    assert any(isinstance(e, CloudAssetUpdated) for e in events)
    assert any(isinstance(e, CloudAssetDiscovered) for e in events)


def test_discover_rejects_blank_provider_id() -> None:
    with pytest.raises(InvalidCloudArgumentError):
        CloudAsset.discover(
            cloud_account_id=CloudAccountId.generate(),
            organization_id=OrganizationId("01HXORG0000000000000000001"),
            asset_type=CloudAssetType.LAMBDA_FUNCTION,
            provider_id="  ",
            region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
            display_name="fn",
            provider_metadata=ProviderMetadata.empty(),
            normalized_config=_config(resource_class="serverless"),
        )


@pytest.mark.parametrize(
    ("asset_type", "payload", "expected_class", "rel_type"),
    [
        (
            CloudAssetType.EC2_INSTANCE,
            {
                "instance_id": "i-1",
                "vpc_id": "vpc-1",
                "security_group_ids": ["sg-1"],
                "tags": [{"Key": "Name", "Value": "web"}],
            },
            "compute",
            CloudAssetRelationshipType.CONTAINED_IN,
        ),
        (
            CloudAssetType.LAMBDA_FUNCTION,
            {
                "function_arn": "arn:aws:lambda:us-east-1:1:function:fn",
                "Role": "arn:aws:iam::1:role/r",
            },
            "serverless",
            CloudAssetRelationshipType.USES_IDENTITY,
        ),
        (
            CloudAssetType.S3_BUCKET,
            {
                "name": "b",
                "arn": "arn:aws:s3:::b",
                "kms_key_id": "arn:aws:kms:us-east-1:1:key/k",
            },
            "storage",
            CloudAssetRelationshipType.ENCRYPTED_BY,
        ),
        (
            CloudAssetType.AZURE_VM,
            {
                "id": (
                    "/subscriptions/s/resourceGroups/rg/providers/"
                    "Microsoft.Compute/virtualMachines/vm1"
                ),
                "name": "vm1",
                "vnet_id": "/vnets/v1",
            },
            "compute",
            CloudAssetRelationshipType.CONTAINED_IN,
        ),
        (
            CloudAssetType.GCP_COMPUTE_INSTANCE,
            {
                "id": "projects/p/zones/z/instances/i1",
                "name": "i1",
                "network": "projects/p/global/networks/default",
            },
            "compute",
            CloudAssetRelationshipType.CONTAINED_IN,
        ),
    ],
)
def test_normalize_raw_asset_relationships(
    asset_type: CloudAssetType,
    payload: dict[str, object],
    expected_class: str,
    rel_type: CloudAssetRelationshipType,
) -> None:
    raw = RawAsset(
        provider_id=str(
            payload.get("arn")
            or payload.get("id")
            or payload.get("function_arn")
            or "id"
        ),
        asset_type=asset_type,
        region_code="us-east-1",
        display_name=str(payload.get("name") or "x"),
        payload=payload,
    )
    draft = normalize_raw_asset(raw)
    assert draft.normalized_config.resource_class == expected_class
    assert any(r.relationship_type is rel_type for r in draft.relationships)


@pytest.mark.asyncio
async def test_aws_adapter_lists_static_assets() -> None:
    client = StaticAwsDiscoveryClient(
        ec2_instances={
            "us-east-1": [
                {
                    "provider_id": "i-abc",
                    "display_name": "web",
                    "vpc_id": "vpc-1",
                    "security_groups": [{"GroupId": "sg-1"}],
                    "tags": [{"Key": "Name", "Value": "web"}],
                }
            ]
        },
        vpcs={
            "us-east-1": [
                {
                    "provider_id": "vpc-1",
                    "display_name": "vpc-1",
                    "CidrBlock": "10.0.0.0/16",
                }
            ]
        },
    )
    adapter = AWSCloudProviderAdapter(client)
    account = type("A", (), {"external_id": "123456789012", "regions": ()})()
    assets = [
        a
        async for a in adapter.list_assets(
            account,  # type: ignore[arg-type]
            [CloudAssetType.EC2_INSTANCE, CloudAssetType.VPC],
        )
    ]
    assert len(assets) >= 2
    assert {a.asset_type for a in assets} >= {CloudAssetType.EC2_INSTANCE, CloudAssetType.VPC}


@pytest.mark.asyncio
async def test_azure_and_gcp_adapters_yield_typed_assets() -> None:
    azure = AzureCloudProviderAdapter(
        StaticAzureDiscoveryClient(
            virtual_machines={
                "eastus": [
                    {
                        "provider_id": (
                            "/subscriptions/s/resourceGroups/rg/providers/"
                            "Microsoft.Compute/virtualMachines/vm1"
                        ),
                        "display_name": "vm1",
                        "vnet_id": "/vnets/v1",
                        "region": "eastus",
                    }
                ]
            }
        )
    )
    gcp = GCPCloudProviderAdapter(
        StaticGcpDiscoveryClient(
            compute_instances={
                "us-central1": [
                    {
                        "provider_id": "projects/p/zones/us-central1-a/instances/i1",
                        "display_name": "i1",
                        "zone": "us-central1-a",
                        "network": "projects/p/global/networks/default",
                    }
                ]
            },
            regions=["us-central1"],
        )
    )
    account = type("A", (), {"external_id": "sub-or-project", "regions": ()})()
    azure_assets = [
        a async for a in azure.list_assets(account, [CloudAssetType.AZURE_VM])  # type: ignore[arg-type]
    ]
    gcp_assets = [
        a
        async for a in gcp.list_assets(
            account,  # type: ignore[arg-type]
            [CloudAssetType.GCP_COMPUTE_INSTANCE],
        )
    ]
    assert len(azure_assets) == 1
    assert azure_assets[0].asset_type is CloudAssetType.AZURE_VM
    assert len(gcp_assets) == 1
    assert gcp_assets[0].asset_type is CloudAssetType.GCP_COMPUTE_INSTANCE

"""Shared fixtures for cloud risk unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.risk.engine import RiskSignalSnapshot
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetType,
    NetworkExposure,
    NormalizedConfig,
    OrganizationId,
    ProviderMetadata,
)


@pytest.fixture
def org_id() -> OrganizationId:
    return OrganizationId("01HXORG0000000000000000001")


@pytest.fixture
def account_id() -> CloudAccountId:
    return CloudAccountId(uuid4())


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def sample_asset(org_id: OrganizationId, account_id: CloudAccountId, now: datetime) -> CloudAsset:
    return CloudAsset.discover(
        cloud_account_id=account_id,
        organization_id=org_id,
        asset_type=CloudAssetType.EC2_INSTANCE,
        provider_id="i-abc123",
        region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
        display_name="web-1",
        provider_metadata=ProviderMetadata.empty(),
        normalized_config=NormalizedConfig(
            schema_version="1",
            resource_class="compute",
            network_exposure=NetworkExposure.PUBLIC,
            encryption_at_rest=False,
            public_endpoints=("https://example.com",),
        ),
        tags={"criticality": "high", "env": "prod"},
        now=now,
    )


@pytest.fixture
def empty_snapshot() -> RiskSignalSnapshot:
    return RiskSignalSnapshot()


@pytest.fixture
def risky_snapshot() -> RiskSignalSnapshot:
    return RiskSignalSnapshot(
        open_finding_severities=("CRITICAL", "HIGH", "MEDIUM"),
        privilege_level="ADMIN",
        network_exposure="PUBLIC",
        encryption_at_rest=False,
        public_accessibility=True,
        compliance_gap_ratio=0.8,
        k8s_security_score=40.0,
        runtime_event_severities=("HIGH",),
        business_criticality="CRITICAL",
        threat_intel_score=5.0,
        tags=(("criticality", "critical"),),
    )

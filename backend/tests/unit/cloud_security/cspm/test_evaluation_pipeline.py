"""Evaluation pipeline and snapshot builder tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from redforge.application.cloud_security.cspm.drift_service import DriftDetectionService
from redforge.application.cloud_security.cspm.evaluation_context_factory import (
    EvaluationContextFactory,
)
from redforge.application.cloud_security.cspm.evaluation_pipeline import EvaluationPipeline
from redforge.application.cloud_security.cspm.resource_snapshot_builder import (
    ResourceSnapshotBuilder,
)
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.cspm.entities import (
    CSPMDriftBaseline,
    RemediationReference,
)
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import (
    DriftKind,
    ResourceSnapshot,
    RuleMetadata,
)
from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetType,
    NetworkExposure,
    NormalizedConfig,
    OrganizationId,
    ProviderMetadata,
)


def _policy(
    policy_id: str,
    asset_type: str = "S3_BUCKET",
    rule: dict[str, object] | None = None,
) -> CSPMPolicy:
    return CSPMPolicy.from_definition(
        policy_id=policy_id,
        rule_id=policy_id,
        title=policy_id,
        description="d",
        severity="HIGH",
        version="1.0.0",
        provider_types=["AWS"],
        asset_types=[asset_type],
        metadata=RuleMetadata(category="storage"),
        remediation=RemediationReference(description="fix"),
        compliance_mapping=[],
        rule=rule
        or {
            "op": "eq",
            "path": "normalized_config.network_exposure",
            "value": "PUBLIC",
        },
    )


def _asset(*, public: bool = True) -> CloudAsset:
    return CloudAsset.discover(
        cloud_account_id=CloudAccountId(uuid4()),
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        asset_type=CloudAssetType.S3_BUCKET,
        provider_id="arn:aws:s3:::bucket",
        region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
        display_name="bucket",
        provider_metadata=ProviderMetadata.empty(),
        normalized_config=NormalizedConfig(
            schema_version="1",
            resource_class="storage",
            network_exposure=NetworkExposure.PUBLIC if public else NetworkExposure.PRIVATE,
            encryption_at_rest=False,
        ),
    )


@pytest.mark.asyncio
async def test_pipeline_detects_violation() -> None:
    pipeline = EvaluationPipeline(batch_size=2, max_workers=2)
    asset = _asset(public=True)
    snap = ResourceSnapshotBuilder().build(asset, provider_type="AWS")
    policies = [
        _policy("P-B"),
        _policy("P-A"),
        _policy(
            "P-C",
            rule={"op": "eq", "path": "normalized_config.network_exposure", "value": "PRIVATE"},
        ),
    ]
    result = await pipeline.evaluate_snapshot(snapshot=snap, policies=policies)
    assert result.policies_evaluated == 3
    assert result.violations == 2
    assert result.passes == 1
    assert [r.policy_id for r in result.results] == ["P-A", "P-B", "P-C"]


@pytest.mark.asyncio
async def test_pipeline_filters_by_policy_ids() -> None:
    pipeline = EvaluationPipeline()
    snap = ResourceSnapshotBuilder().build(_asset(), provider_type="AWS")
    policies = [_policy("P1"), _policy("P2")]
    result = await pipeline.evaluate_snapshot(
        snapshot=snap, policies=policies, policy_ids=("P2",)
    )
    assert result.policies_evaluated == 1
    assert result.results[0].policy_id == "P2"


@pytest.mark.asyncio
async def test_pipeline_skips_wrong_provider() -> None:
    pipeline = EvaluationPipeline()
    snap = ResourceSnapshotBuilder().build(_asset(), provider_type="GCP")
    policies = [_policy("P1")]
    result = await pipeline.evaluate_snapshot(snapshot=snap, policies=policies)
    assert result.policies_evaluated == 0


def test_snapshot_builder_includes_nested_config() -> None:
    asset = _asset()
    snap = ResourceSnapshotBuilder().build(asset, provider_type="aws")
    assert snap.provider_type == "AWS"
    assert snap.normalized_config["network_exposure"] == "PUBLIC"
    d = snap.to_dict()
    assert d["normalized_config"]["encryption_at_rest"] is False
    assert "cloud_asset_id" in d


def test_evaluation_context_factory() -> None:
    ctx = EvaluationContextFactory().build(
        organization_id="org",
        evaluation_id="e1",
        triggered_by="user",
        cloud_account_id="acc",
        policy_ids=("P1",),
    )
    assert ctx.evaluation_id == "e1"
    assert ctx.to_dict()["policy_ids"] == ["P1"]


class _MemDriftRepo:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str, str], CSPMDriftBaseline] = {}

    async def save(self, baseline: CSPMDriftBaseline) -> None:
        key = (baseline.organization_id, str(baseline.cloud_asset_id), baseline.drift_kind)
        self.items[key] = baseline

    async def get_by_asset(self, organization_id, cloud_asset_id, drift_kind):
        return self.items.get((str(organization_id), str(cloud_asset_id), drift_kind))

    async def get_by_id(self, baseline_id, organization_id):
        for item in self.items.values():
            if item.id == baseline_id and item.organization_id == str(organization_id):
                return item
        return None


@pytest.mark.asyncio
async def test_drift_service_creates_and_detects() -> None:
    repo = _MemDriftRepo()
    svc = DriftDetectionService(repo)  # type: ignore[arg-type]
    snap = ResourceSnapshot(
        cloud_asset_id=str(uuid4()),
        organization_id="01HXORG0000000000000000001",
        cloud_account_id=str(uuid4()),
        asset_type="S3_BUCKET",
        provider_type="AWS",
        provider_id="arn",
        display_name="b",
        region_code="us-east-1",
        tags={},
        normalized_config={"network_exposure": "PUBLIC"},
        config_hash="hash1",
        captured_at=datetime.now(UTC),
    )
    _b, d1 = await svc.ensure_baseline(snapshot=snap)
    assert d1.drifted is False
    assert d1.message == "baseline_created"
    snap2 = ResourceSnapshot(
        cloud_asset_id=snap.cloud_asset_id,
        organization_id=snap.organization_id,
        cloud_account_id=snap.cloud_account_id,
        asset_type=snap.asset_type,
        provider_type=snap.provider_type,
        provider_id=snap.provider_id,
        display_name=snap.display_name,
        region_code=snap.region_code,
        tags={},
        normalized_config={"network_exposure": "PRIVATE"},
        config_hash="hash2",
        captured_at=datetime.now(UTC),
    )
    _b2, d2 = await svc.ensure_baseline(snapshot=snap2, drift_kind=DriftKind.CONFIGURATION)
    assert d2.drifted is True
    updated = await svc.update_baseline(snapshot=snap2)
    assert updated.baseline_hash == "hash2"
    payload = svc.diagnostics_to_dict([d2])
    assert payload["drift"][0]["drifted"] is True

"""PostgreSQL integration tests for CSPM repositories."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.cspm.entities import (
    CSPMDriftBaseline,
    FindingEvidence,
    RemediationReference,
)
from redforge.domain.cloud_security.cspm.evaluation import CSPMEvaluation
from redforge.domain.cloud_security.cspm.finding import CSPMFinding
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import (
    ComplianceRef,
    EvaluationContext,
    FindingSeverity,
    FindingStatus,
    RuleMetadata,
)
from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudAssetType,
    CloudProviderType,
    CredentialRef,
    NetworkExposure,
    NormalizedConfig,
    OrganizationId,
    ProviderMetadata,
)
from redforge.infrastructure.cloud_security.cspm.repositories import (
    PgCSPMDriftBaselineRepository,
    PgCSPMEvaluationRepository,
    PgCSPMFindingRepository,
    PgCSPMPolicyRepository,
)
from redforge.infrastructure.cloud_security.persistence.repositories import (
    PgCloudAccountRepository,
    PgCloudAssetRepository,
    PgCloudProviderRepository,
)

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_cspm_policy_finding_evaluation_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        providers = PgCloudProviderRepository(session)
        accounts = PgCloudAccountRepository(session)
        assets = PgCloudAssetRepository(session)
        policies = PgCSPMPolicyRepository(session)
        findings = PgCSPMFindingRepository(session)
        evaluations = PgCSPMEvaluationRepository(session)
        drifts = PgCSPMDriftBaselineRepository(session)

        provider = CloudProvider.register(
            organization_id=org,
            provider_type=CloudProviderType.AWS,
            display_name="CSPM AWS",
        )
        await providers.save(provider)
        account = CloudAccount.register(
            cloud_provider_id=provider.id,
            organization_id=org,
            external_id="999988887777",
            display_name="Acct",
            account_type=CloudAccountType.STANDALONE,
            credential_ref=CredentialRef(reference_id="cred-cspm"),
        )
        await accounts.save(account)
        asset = CloudAsset.discover(
            cloud_account_id=account.id,
            organization_id=org,
            asset_type=CloudAssetType.S3_BUCKET,
            provider_id="arn:aws:s3:::cspm-test",
            region=CloudRegion(region_code="us-east-1", display_name="us-east-1"),
            display_name="cspm-test",
            provider_metadata=ProviderMetadata.empty(),
            normalized_config=NormalizedConfig(
                schema_version="1",
                resource_class="storage",
                network_exposure=NetworkExposure.PUBLIC,
                encryption_at_rest=False,
            ),
        )
        await assets.save(asset)

        policy = CSPMPolicy.from_definition(
            policy_id=f"CSPM-TEST-{uuid4().hex[:8]}",
            rule_id="TEST_RULE",
            title="Test policy",
            description="desc",
            severity="HIGH",
            version="1.0.0",
            provider_types=["AWS"],
            asset_types=["S3_BUCKET"],
            metadata=RuleMetadata(category="storage", tags=("test",)),
            remediation=RemediationReference(description="fix"),
            compliance_mapping=[
                ComplianceRef(framework_key="cis_benchmarks_v8", requirement_ref="3.3")
            ],
            rule={
                "op": "eq",
                "path": "normalized_config.network_exposure",
                "value": "PUBLIC",
            },
        )
        await policies.save(policy)
        loaded = await policies.get_by_id(policy.id)
        assert loaded is not None
        assert loaded.title == "Test policy"
        enabled = await policies.list_for_asset(provider_type="AWS", asset_type="S3_BUCKET")
        assert any(str(p.id) == str(policy.id) for p in enabled)

        finding = CSPMFinding.open(
            cloud_asset_id=asset.id,
            organization_id=org,
            policy_id=policy.id,
            rule_id=policy.rule_id,
            severity=FindingSeverity.HIGH,
            title=policy.title,
            description=policy.description,
            remediation=policy.remediation,
            compliance_mapping=list(policy.compliance_mapping),
            evidence=[
                FindingEvidence.create(
                    path="normalized_config.network_exposure",
                    expected="PRIVATE",
                    actual="PUBLIC",
                    message="public",
                )
            ],
            config_hash=asset.posture_state.config_hash,
        )
        await findings.save(finding)
        by_fp = await findings.get_by_fingerprint(finding.fingerprint, org)
        assert by_fp is not None
        assert by_fp.status is FindingStatus.OPEN
        page = await findings.list_by_organization(org, page=1, size=10)
        assert page.total >= 1
        open_list = await findings.list_open_by_asset(asset.id, org)
        assert open_list
        counts = await findings.count_open_by_severity(org)
        assert counts.get("HIGH", 0) >= 1

        evaluation = CSPMEvaluation.start(
            organization_id=org,
            context=EvaluationContext(
                organization_id=str(org),
                cloud_account_id=str(account.id),
                evaluation_id="pending",
                triggered_by="test",
            ),
            cloud_account_id=str(account.id),
        )
        evaluation.complete(
            assets_evaluated=1,
            policies_evaluated=1,
            findings_opened=1,
            findings_resolved=0,
            diagnostics={"ok": True},
        )
        await evaluations.save(evaluation)
        loaded_eval = await evaluations.get_by_id(evaluation.id, org)
        assert loaded_eval is not None
        assert loaded_eval.findings_opened == 1
        eval_page = await evaluations.list_by_organization(org, page=1, size=10)
        assert eval_page.total >= 1

        baseline = CSPMDriftBaseline.create(
            organization_id=str(org),
            cloud_asset_id=asset.id.value,
            drift_kind="CONFIGURATION",
            baseline_hash=asset.posture_state.config_hash,
            baseline_snapshot={"config_hash": asset.posture_state.config_hash},
        )
        await drifts.save(baseline)
        loaded_drift = await drifts.get_by_asset(org, asset.id, "CONFIGURATION")
        assert loaded_drift is not None
        assert loaded_drift.baseline_hash == asset.posture_state.config_hash

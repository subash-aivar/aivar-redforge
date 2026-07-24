from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from uuid import UUID

import pytest

from cloud_security.application.commands.baseline_commands import (
    BatchBaselineCommand,
    EvaluateAccountCommand,
    EvaluateAssetCommand,
    EvaluateOrganizationCommand,
    RefreshBaselineCommand,
)
from cloud_security.application.dtos.baseline_outcomes import BatchBaselineStatus
from cloud_security.application.exceptions import (
    AccountMismatchError,
    DuplicateEvaluationError,
    EmptyBatchBaselineError,
    EvaluationNotFoundError,
    MissingBaselineCapabilityError,
    NoBaselineProviderRegisteredError,
    ProviderNotEnabledError,
    UnsupportedProviderError,
)
from cloud_security.application.queries.baseline_queries import (
    BaselineStatisticsQuery,
    GetBaselineResultQuery,
    ListBaselineFindingsQuery,
    ListFailedEvaluationsQuery,
)
from cloud_security.application.registry.in_memory_baseline_registry import (
    InMemoryBaselineRegistry,
)
from cloud_security.application.registry.in_memory_provider_registry import (
    InMemoryProviderRegistry,
)
from cloud_security.application.services.baseline_application_service import (
    BaselineApplicationService,
)
from cloud_security.domain.aggregates.cloud_account import CloudAccount
from cloud_security.domain.aggregates.cloud_asset import CloudAsset
from cloud_security.domain.aggregates.cloud_provider_registration import (
    CloudProviderRegistration,
)
from cloud_security.domain.aggregates.cloud_security_evaluation import CloudSecurityEvaluation
from cloud_security.domain.value_objects.baseline_finding import BaselineFinding
from cloud_security.domain.value_objects.cloud_metadata import CloudMetadata
from cloud_security.domain.value_objects.cloud_resource import CloudResource
from cloud_security.domain.value_objects.cloud_tag import CloudTagSet
from cloud_security.domain.value_objects.enums import (
    CloudAssetType,
    CloudPlatformType,
    CloudRiskLevel,
    CloudSeverity,
    FindingCategory,
    FindingStatus,
    ProviderCapability,
)
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    AssetId,
    EvaluationId,
    FindingId,
    ProviderId,
    ResourceId,
    RuleId,
    TenantId,
)
from cloud_security.domain.value_objects.provider_capability_set import ProviderCapabilitySet

NOW = datetime.now(UTC)


class FakeBaselineProvider:
    def __init__(self, platform_type, findings_per_asset=None, error=None):
        self._platform_type = platform_type
        self._findings_per_asset = findings_per_asset or {}
        self._error = error

    @property
    def platform_type(self):
        return self._platform_type

    def evaluate(self, asset):
        if self._error is not None:
            raise self._error
        return self._findings_per_asset.get(str(asset.asset_id), ())


def _resource(native_id: str = "i-1") -> CloudResource:
    return CloudResource(
        resource_id=ResourceId(native_id),
        native_id=native_id,
        asset_type=CloudAssetType.COMPUTE_INSTANCE,
    )


def _asset(tenant_id, account_id, **overrides) -> CloudAsset:
    defaults = {
        "asset_id": AssetId.generate(),
        "tenant_id": tenant_id,
        "account_id": account_id,
        "resource": _resource(),
        "tags": CloudTagSet(),
        "risk_level": CloudRiskLevel.LOW,
        "metadata": CloudMetadata(),
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudAsset.discover(**defaults)


def _finding(asset_id) -> BaselineFinding:
    return BaselineFinding(
        finding_id=FindingId.generate(),
        asset_id=asset_id,
        severity=CloudSeverity.HIGH,
        category=FindingCategory.NETWORKING,
        rule_id=RuleId("cs-001"),
        rule_name="Unrestricted ingress",
        description="Security group allows 0.0.0.0/0",
        recommendation="Restrict ingress",
        evidence_reference="evidence://x",
        status=FindingStatus.OPEN,
        detected_at=NOW,
    )


class Harness:
    def __init__(self, provider_enabled=True, with_baseline_capability=True):
        self.tenant_id = TenantId.generate()
        self.account = CloudAccount.register(
            account_id=AccountId.generate(),
            tenant_id=self.tenant_id,
            provider_id=ProviderId.generate(),
            platform_type=CloudPlatformType.AWS,
            display_name="prod-account",
            tags=CloudTagSet(),
            now=NOW,
        )

        capabilities = ProviderCapabilitySet(
            capabilities=(ProviderCapability.SECURITY_BASELINE,)
            if with_baseline_capability
            else ()
        )
        self.provider = CloudProviderRegistration.register(
            provider_id=ProviderId.generate(),
            tenant_id=self.tenant_id,
            platform_type=CloudPlatformType.AWS,
            display_name="aws-primary",
            capabilities=capabilities,
            now=NOW,
        )
        if provider_enabled:
            self.provider.enable(self.tenant_id, NOW)

        self.provider_registry = InMemoryProviderRegistry()
        self.provider_registry.register(self.provider)

        self.evaluation_registry = InMemoryBaselineRegistry()
        self.baseline_providers = {
            CloudPlatformType.AWS: FakeBaselineProvider(CloudPlatformType.AWS)
        }

        self.service = BaselineApplicationService(
            evaluation_registry=self.evaluation_registry,
            provider_registry=self.provider_registry,
            baseline_providers=self.baseline_providers,
        )

    def asset_cmd(self, asset_id, **overrides) -> EvaluateAssetCommand:
        defaults = {
            "tenant_id": self.tenant_id,
            "account_id": self.account.account_id,
            "provider_id": self.provider.provider_id,
            "asset_id": asset_id,
        }
        defaults.update(overrides)
        return EvaluateAssetCommand(**defaults)

    def account_cmd(self, **overrides) -> EvaluateAccountCommand:
        defaults = {
            "tenant_id": self.tenant_id,
            "account_id": self.account.account_id,
            "provider_id": self.provider.provider_id,
        }
        defaults.update(overrides)
        return EvaluateAccountCommand(**defaults)


# ---------------------------------------------------------------------------
# evaluation / finding generation
# ---------------------------------------------------------------------------


def test_evaluate_asset_produces_findings() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    finding = _finding(asset.asset_id)
    h.baseline_providers[CloudPlatformType.AWS] = FakeBaselineProvider(
        CloudPlatformType.AWS, findings_per_asset={str(asset.asset_id): (finding,)}
    )

    outcome = h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)

    assert outcome.record.status.value == "completed"
    assert outcome.record.evaluated_asset_count == 1
    assert outcome.record.finding_count == 1
    assert outcome.record.findings[0].rule_name == "Unrestricted ingress"


def test_evaluate_asset_with_no_findings() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)

    outcome = h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)

    assert outcome.record.finding_count == 0
    assert outcome.record.evaluated_asset_count == 1


def test_evaluate_account_evaluates_all_assets() -> None:
    h = Harness()
    asset1 = _asset(h.tenant_id, h.account.account_id, resource=_resource("i-1"))
    asset2 = _asset(h.tenant_id, h.account.account_id, resource=_resource("i-2"))
    h.baseline_providers[CloudPlatformType.AWS] = FakeBaselineProvider(
        CloudPlatformType.AWS,
        findings_per_asset={str(asset1.asset_id): (_finding(asset1.asset_id),)},
    )

    outcome = h.service.evaluate_account(h.account_cmd(), h.account, (asset1, asset2))

    assert outcome.record.evaluated_asset_count == 2
    assert outcome.record.finding_count == 1


def test_decommissioned_asset_counts_as_failed_not_aborting_run() -> None:
    h = Harness()
    active_asset = _asset(h.tenant_id, h.account.account_id, resource=_resource("i-1"))
    decommissioned_asset = _asset(h.tenant_id, h.account.account_id, resource=_resource("i-2"))
    decommissioned_asset.decommission(h.tenant_id, NOW)

    outcome = h.service.evaluate_account(
        h.account_cmd(), h.account, (active_asset, decommissioned_asset)
    )

    assert outcome.record.status.value == "completed"
    assert outcome.record.evaluated_asset_count == 1
    assert outcome.record.failed_count == 1


def test_provider_exception_is_isolated_per_asset() -> None:
    h = Harness()
    asset1 = _asset(h.tenant_id, h.account.account_id, resource=_resource("i-1"))
    asset2 = _asset(h.tenant_id, h.account.account_id, resource=_resource("i-2"))
    h.baseline_providers[CloudPlatformType.AWS] = FakeBaselineProvider(
        CloudPlatformType.AWS, error=RuntimeError("evaluator crashed")
    )

    outcome = h.service.evaluate_account(h.account_cmd(), h.account, (asset1, asset2))

    assert outcome.record.status.value == "completed"
    assert outcome.record.failed_count == 2
    assert outcome.record.evaluated_asset_count == 0


def test_asset_never_mutated_by_evaluation() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    asset.pop_events()
    original_updated_at = asset.updated_at

    h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)

    assert asset.updated_at == original_updated_at
    assert asset.pop_events() == []


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def test_account_mismatch_raises() -> None:
    h = Harness()
    other_account = CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=h.tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="other-account",
        tags=CloudTagSet(),
        now=NOW,
    )
    asset = _asset(h.tenant_id, h.account.account_id)

    with pytest.raises(AccountMismatchError):
        h.service.evaluate_asset(h.asset_cmd(asset.asset_id), other_account, asset)


def test_unknown_provider_raises() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    with pytest.raises(UnsupportedProviderError):
        h.service.evaluate_asset(
            h.asset_cmd(asset.asset_id, provider_id=ProviderId.generate()), h.account, asset
        )


def test_disabled_provider_raises() -> None:
    h = Harness(provider_enabled=False)
    asset = _asset(h.tenant_id, h.account.account_id)
    with pytest.raises(ProviderNotEnabledError):
        h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)


def test_missing_baseline_capability_raises() -> None:
    h = Harness(with_baseline_capability=False)
    asset = _asset(h.tenant_id, h.account.account_id)
    with pytest.raises(MissingBaselineCapabilityError):
        h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)


def test_no_registered_baseline_provider_raises() -> None:
    h = Harness()
    h.baseline_providers.clear()
    asset = _asset(h.tenant_id, h.account.account_id)

    with pytest.raises(NoBaselineProviderRegisteredError):
        h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)


def test_duplicate_evaluation_raises() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    lingering = CloudSecurityEvaluation.start(
        evaluation_id=EvaluationId.generate(),
        tenant_id=h.tenant_id,
        account_id=h.account.account_id,
        provider_id=h.provider.provider_id,
        now=NOW,
    )
    h.evaluation_registry.register(lingering)

    with pytest.raises(DuplicateEvaluationError):
        h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)


# ---------------------------------------------------------------------------
# refresh / organization / batch
# ---------------------------------------------------------------------------


def test_refresh_baseline_creates_new_evaluation() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    first = h.service.evaluate_account(h.account_cmd(), h.account, (asset,))
    evaluation_id = EvaluationId(UUID(first.record.evaluation_id))

    refreshed = h.service.refresh_baseline(
        RefreshBaselineCommand(tenant_id=h.tenant_id, evaluation_id=evaluation_id),
        h.account,
        (asset,),
    )

    assert refreshed.record.evaluation_id != first.record.evaluation_id
    assert refreshed.record.status.value == "completed"


def test_refresh_unknown_evaluation_raises() -> None:
    h = Harness()
    with pytest.raises(EvaluationNotFoundError):
        h.service.refresh_baseline(
            RefreshBaselineCommand(tenant_id=h.tenant_id, evaluation_id=EvaluationId.generate()),
            h.account,
            (),
        )


def test_evaluate_organization_runs_all_accounts() -> None:
    h = Harness()
    other_account = CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=h.tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="second-account",
        tags=CloudTagSet(),
        now=NOW,
    )
    accounts = {str(h.account.account_id): h.account, str(other_account.account_id): other_account}
    assets_by_account = {
        str(h.account.account_id): (_asset(h.tenant_id, h.account.account_id),),
        str(other_account.account_id): (_asset(h.tenant_id, other_account.account_id),),
    }

    result = h.service.evaluate_organization(
        EvaluateOrganizationCommand(
            tenant_id=h.tenant_id,
            provider_id=h.provider.provider_id,
            account_ids=(h.account.account_id, other_account.account_id),
        ),
        accounts,
        assets_by_account,
    )

    assert result.status == BatchBaselineStatus.SUCCEEDED
    assert result.succeeded_count == 2


def test_batch_baseline_partial_failure() -> None:
    h = Harness()
    other_account = CloudAccount.register(
        account_id=AccountId.generate(),
        tenant_id=h.tenant_id,
        provider_id=ProviderId.generate(),
        platform_type=CloudPlatformType.AWS,
        display_name="mismatched-account",
        tags=CloudTagSet(),
        now=NOW,
    )
    accounts = {str(h.account.account_id): h.account, str(other_account.account_id): other_account}
    commands = (
        h.account_cmd(),
        EvaluateAccountCommand(
            tenant_id=h.tenant_id,
            account_id=other_account.account_id,
            provider_id=ProviderId.generate(),  # unregistered provider -> fails
        ),
    )

    result = h.service.register_batch(
        BatchBaselineCommand(tenant_id=h.tenant_id, commands=commands), accounts, {}
    )

    assert result.status == BatchBaselineStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1
    assert result.failed_count == 1


def test_batch_baseline_empty_raises() -> None:
    h = Harness()
    with pytest.raises(EmptyBatchBaselineError):
        h.service.register_batch(BatchBaselineCommand(tenant_id=h.tenant_id, commands=()), {}, {})


# ---------------------------------------------------------------------------
# queries
# ---------------------------------------------------------------------------


def test_get_baseline_result_returns_none_when_missing() -> None:
    h = Harness()
    result = h.service.get_baseline_result(
        GetBaselineResultQuery(tenant_id=h.tenant_id, evaluation_id=EvaluationId.generate())
    )
    assert result is None


def test_list_baseline_findings() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    finding = _finding(asset.asset_id)
    h.baseline_providers[CloudPlatformType.AWS] = FakeBaselineProvider(
        CloudPlatformType.AWS, findings_per_asset={str(asset.asset_id): (finding,)}
    )
    outcome = h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)
    evaluation_id = EvaluationId(UUID(outcome.record.evaluation_id))

    findings = h.service.list_baseline_findings(
        ListBaselineFindingsQuery(tenant_id=h.tenant_id, evaluation_id=evaluation_id)
    )
    assert len(findings) == 1


def test_list_baseline_findings_unknown_evaluation_raises() -> None:
    h = Harness()
    with pytest.raises(EvaluationNotFoundError):
        h.service.list_baseline_findings(
            ListBaselineFindingsQuery(tenant_id=h.tenant_id, evaluation_id=EvaluationId.generate())
        )


def test_list_failed_evaluations() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    h.baseline_providers[CloudPlatformType.AWS] = FakeBaselineProvider(
        CloudPlatformType.AWS, error=RuntimeError("boom")
    )

    h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)

    failed = h.service.list_failed_evaluations(ListFailedEvaluationsQuery(tenant_id=h.tenant_id))
    # a per-asset failure does not fail the whole evaluation (still completes)
    assert failed == ()


def test_baseline_statistics() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    finding = _finding(asset.asset_id)
    h.baseline_providers[CloudPlatformType.AWS] = FakeBaselineProvider(
        CloudPlatformType.AWS, findings_per_asset={str(asset.asset_id): (finding,)}
    )

    h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)

    stats = h.service.baseline_statistics(BaselineStatisticsQuery(tenant_id=h.tenant_id))
    assert stats.total_evaluations == 1
    assert stats.completed_evaluations == 1
    assert stats.total_assets_evaluated == 1
    assert stats.total_findings == 1


# ---------------------------------------------------------------------------
# tenant isolation
# ---------------------------------------------------------------------------


def test_evaluations_are_tenant_isolated() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)

    other_tenant_stats = h.service.baseline_statistics(
        BaselineStatisticsQuery(tenant_id=TenantId.generate())
    )
    assert other_tenant_stats.total_evaluations == 0


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_baseline_completed_outcome_is_frozen() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    outcome = h.service.evaluate_asset(h.asset_cmd(asset.asset_id), h.account, asset)
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.record = None  # type: ignore[misc]


def test_batch_baseline_result_is_frozen() -> None:
    h = Harness()
    asset = _asset(h.tenant_id, h.account.account_id)
    result = h.service.register_batch(
        BatchBaselineCommand(tenant_id=h.tenant_id, commands=(h.account_cmd(),)),
        {str(h.account.account_id): h.account},
        {str(h.account.account_id): (asset,)},
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = BatchBaselineStatus.FAILED  # type: ignore[misc]

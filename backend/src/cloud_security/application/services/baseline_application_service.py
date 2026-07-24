"""BaselineApplicationService — the canonical entrypoint for every
Security Baseline / CSPM Foundation operation (M45F).

Resolves a registered `IBaselineProvider`, reads (never mutates)
`CloudAsset`s handed in by the caller, evaluates them against the
provider's baseline rules, and produces immutable `BaselineFinding`s
tracked on a `CloudSecurityEvaluation`. This service never performs
compliance-framework mapping, never calculates a risk score, never
executes remediation — it only evaluates and reports. `CloudAsset`
(M45B) remains the single, read-only-from-this-context inventory:
every asset is a caller-supplied instance (no persistence, the same
discipline every prior `cloud_security` service follows) and is never
written back to. This service holds no state between calls beyond its
injected collaborators, so it stays stateless."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.commands.baseline_commands import EvaluateAccountCommand
from cloud_security.application.dtos.baseline_evaluation_record import BaselineEvaluationRecord
from cloud_security.application.dtos.baseline_finding_record import BaselineFindingRecord
from cloud_security.application.dtos.baseline_outcomes import (
    BaselineCompleted,
    BaselineStatistics,
    BatchBaselineFailure,
    BatchBaselineResult,
    BatchBaselineStatus,
)
from cloud_security.application.exceptions import (
    EvaluationNotFoundError,
    NoBaselineProviderRegisteredError,
    UnsupportedProviderError,
)
from cloud_security.application.services import baseline_validation
from cloud_security.domain.aggregates.cloud_security_evaluation import CloudSecurityEvaluation
from cloud_security.domain.value_objects.enums import EvaluationStatus
from cloud_security.domain.value_objects.identifiers import EvaluationId

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from cloud_security.application.commands.baseline_commands import (
        BatchBaselineCommand,
        EvaluateAssetCommand,
        EvaluateOrganizationCommand,
        RefreshBaselineCommand,
    )
    from cloud_security.application.ports.i_baseline_provider import IBaselineProvider
    from cloud_security.application.ports.i_baseline_registry import IBaselineRegistry
    from cloud_security.application.ports.i_provider_registry import IProviderRegistry
    from cloud_security.application.queries.baseline_queries import (
        BaselineStatisticsQuery,
        GetBaselineResultQuery,
        ListBaselineFindingsQuery,
        ListFailedEvaluationsQuery,
    )
    from cloud_security.domain.aggregates.cloud_account import CloudAccount
    from cloud_security.domain.aggregates.cloud_asset import CloudAsset
    from cloud_security.domain.value_objects.baseline_finding import BaselineFinding
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import (
        AccountId,
        ProviderId,
        TenantId,
    )


def _finding_to_record(finding: BaselineFinding) -> BaselineFindingRecord:
    return BaselineFindingRecord(
        finding_id=str(finding.finding_id),
        asset_id=str(finding.asset_id),
        severity=finding.severity,
        category=finding.category,
        rule_id=str(finding.rule_id),
        rule_name=finding.rule_name,
        description=finding.description,
        recommendation=finding.recommendation,
        evidence_reference=finding.evidence_reference,
        status=finding.status,
        detected_at=finding.detected_at,
    )


def _to_record(evaluation: CloudSecurityEvaluation) -> BaselineEvaluationRecord:
    return BaselineEvaluationRecord(
        evaluation_id=str(evaluation.evaluation_id),
        tenant_id=str(evaluation.tenant_id),
        account_id=str(evaluation.account_id),
        provider_id=str(evaluation.provider_id),
        status=evaluation.status,
        started_at=evaluation.started_at,
        evaluated_asset_count=evaluation.evaluated_asset_count,
        finding_count=evaluation.finding_count,
        failed_count=evaluation.failed_count,
        findings=tuple(_finding_to_record(f) for f in evaluation.findings),
        completed_at=evaluation.completed_at,
        failure_reason=evaluation.failure_reason,
    )


class BaselineApplicationService:
    def __init__(
        self,
        evaluation_registry: IBaselineRegistry,
        provider_registry: IProviderRegistry,
        baseline_providers: Mapping[CloudPlatformType, IBaselineProvider],
    ) -> None:
        self._evaluation_registry = evaluation_registry
        self._provider_registry = provider_registry
        self._baseline_providers = baseline_providers

    # -- commands ------------------------------------------------------

    def evaluate_asset(
        self, cmd: EvaluateAssetCommand, account: CloudAccount, asset: CloudAsset
    ) -> BaselineCompleted:
        baseline_validation.validate_account_matches(account, cmd.account_id)
        return self._run_evaluation(cmd.tenant_id, cmd.account_id, cmd.provider_id, (asset,))

    def evaluate_account(
        self, cmd: EvaluateAccountCommand, account: CloudAccount, assets: Sequence[CloudAsset]
    ) -> BaselineCompleted:
        baseline_validation.validate_account_matches(account, cmd.account_id)
        return self._run_evaluation(cmd.tenant_id, cmd.account_id, cmd.provider_id, assets)

    def evaluate_organization(
        self,
        cmd: EvaluateOrganizationCommand,
        accounts: Mapping[str, CloudAccount],
        assets_by_account: Mapping[str, Sequence[CloudAsset]],
    ) -> BatchBaselineResult:
        sub_commands = tuple(
            EvaluateAccountCommand(
                tenant_id=cmd.tenant_id, account_id=account_id, provider_id=cmd.provider_id
            )
            for account_id in cmd.account_ids
        )
        return self._run_batch(sub_commands, accounts, assets_by_account)

    def register_batch(
        self,
        cmd: BatchBaselineCommand,
        accounts: Mapping[str, CloudAccount],
        assets_by_account: Mapping[str, Sequence[CloudAsset]],
    ) -> BatchBaselineResult:
        baseline_validation.validate_batch_not_empty(cmd.commands)
        return self._run_batch(cmd.commands, accounts, assets_by_account)

    def _run_batch(
        self,
        commands: tuple[EvaluateAccountCommand, ...],
        accounts: Mapping[str, CloudAccount],
        assets_by_account: Mapping[str, Sequence[CloudAsset]],
    ) -> BatchBaselineResult:
        completed: list[BaselineCompleted] = []
        failures: list[BatchBaselineFailure] = []
        for index, sub_cmd in enumerate(commands):
            try:
                account = accounts[str(sub_cmd.account_id)]
                assets = assets_by_account.get(str(sub_cmd.account_id), ())
                completed.append(self.evaluate_account(sub_cmd, account, assets))
            except Exception as exc:
                failures.append(
                    BatchBaselineFailure(
                        index=index, error_type=type(exc).__name__, message=str(exc)
                    )
                )

        if not failures:
            status = BatchBaselineStatus.SUCCEEDED
        elif not completed:
            status = BatchBaselineStatus.FAILED
        else:
            status = BatchBaselineStatus.PARTIALLY_SUCCEEDED

        return BatchBaselineResult(
            status=status, completed=tuple(completed), failures=tuple(failures)
        )

    def refresh_baseline(
        self, cmd: RefreshBaselineCommand, account: CloudAccount, assets: Sequence[CloudAsset]
    ) -> BaselineCompleted:
        old_evaluation = self._require_evaluation(cmd.tenant_id, cmd.evaluation_id)
        new_cmd = EvaluateAccountCommand(
            tenant_id=cmd.tenant_id,
            account_id=old_evaluation.account_id,
            provider_id=old_evaluation.provider_id,
        )
        return self.evaluate_account(new_cmd, account, assets)

    def _run_evaluation(
        self,
        tenant_id: TenantId,
        account_id: AccountId,
        provider_id: ProviderId,
        assets: Sequence[CloudAsset],
    ) -> BaselineCompleted:
        provider_record = self._provider_registry.get(tenant_id, provider_id)
        if provider_record is None:
            raise UnsupportedProviderError(provider_id)
        baseline_validation.validate_provider_enabled(provider_record)
        baseline_validation.validate_provider_has_baseline_capability(provider_record)

        baseline_provider = self._baseline_providers.get(provider_record.platform_type)
        if baseline_provider is None:
            raise NoBaselineProviderRegisteredError(provider_record.platform_type)

        now = datetime.now(UTC)
        evaluation = CloudSecurityEvaluation.start(
            evaluation_id=EvaluationId.generate(),
            tenant_id=tenant_id,
            account_id=account_id,
            provider_id=provider_id,
            now=now,
        )
        self._evaluation_registry.register(evaluation)

        for asset in assets:
            try:
                baseline_validation.validate_asset_active(asset)
                findings = tuple(baseline_provider.evaluate(asset))
                evaluation.record_asset_evaluated(tenant_id, findings)
            except Exception:
                evaluation.record_failure(tenant_id)

        evaluation.complete(tenant_id, datetime.now(UTC))
        self._evaluation_registry.release(evaluation)
        return BaselineCompleted(record=_to_record(evaluation))

    def _require_evaluation(
        self, tenant_id: TenantId, evaluation_id: EvaluationId
    ) -> CloudSecurityEvaluation:
        evaluation = self._evaluation_registry.get(tenant_id, evaluation_id)
        if evaluation is None:
            raise EvaluationNotFoundError(evaluation_id)
        return evaluation

    # -- queries ---------------------------------------------------------

    def get_baseline_result(
        self, query: GetBaselineResultQuery
    ) -> BaselineEvaluationRecord | None:
        evaluation = self._evaluation_registry.get(query.tenant_id, query.evaluation_id)
        return _to_record(evaluation) if evaluation is not None else None

    def list_baseline_findings(
        self, query: ListBaselineFindingsQuery
    ) -> tuple[BaselineFindingRecord, ...]:
        evaluation = self._require_evaluation(query.tenant_id, query.evaluation_id)
        return tuple(_finding_to_record(f) for f in evaluation.findings)

    def list_failed_evaluations(
        self, query: ListFailedEvaluationsQuery
    ) -> tuple[BaselineEvaluationRecord, ...]:
        return tuple(
            _to_record(e)
            for e in self._evaluation_registry.list_failed(query.tenant_id, query.account_id)
        )

    def baseline_statistics(self, query: BaselineStatisticsQuery) -> BaselineStatistics:
        evaluations = self._evaluation_registry.list(query.tenant_id, query.account_id)
        return BaselineStatistics(
            total_evaluations=len(evaluations),
            in_progress_evaluations=sum(
                1 for e in evaluations if e.status == EvaluationStatus.IN_PROGRESS
            ),
            completed_evaluations=sum(
                1 for e in evaluations if e.status == EvaluationStatus.COMPLETED
            ),
            failed_evaluations=sum(1 for e in evaluations if e.status == EvaluationStatus.FAILED),
            total_assets_evaluated=sum(e.evaluated_asset_count for e in evaluations),
            total_findings=sum(e.finding_count for e in evaluations),
        )

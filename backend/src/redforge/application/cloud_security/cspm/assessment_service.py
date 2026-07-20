"""CSPM assessment service — evaluate assets/accounts, manage findings."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.application.cloud_security.cspm.drift_service import DriftDetectionService
from redforge.application.cloud_security.cspm.dtos import (
    ComplianceRefDTO,
    ComplianceSummaryDTO,
    CSPMEvaluationDTO,
    CSPMEvaluationPageDTO,
    CSPMFindingDTO,
    CSPMFindingPageDTO,
    CSPMPolicyDTO,
    EvaluateAssetCommand,
    EvaluationResultDTO,
    FindingEvidenceDTO,
    FindingSummaryDTO,
    GetEvaluationQuery,
    GetFindingQuery,
    GetPolicyQuery,
    ListEvaluationsQuery,
    ListFindingsQuery,
    ListPoliciesQuery,
    SummaryQuery,
    TriggerCSPMEvaluationCommand,
    UpdateFindingStatusCommand,
)
from redforge.application.cloud_security.cspm.evaluation_context_factory import (
    EvaluationContextFactory,
)
from redforge.application.cloud_security.cspm.evaluation_pipeline import EvaluationPipeline
from redforge.application.cloud_security.cspm.resource_snapshot_builder import (
    ResourceSnapshotBuilder,
)
from redforge.domain.cloud_security.cspm.entities import FindingEvidence
from redforge.domain.cloud_security.cspm.evaluation import CSPMEvaluation
from redforge.domain.cloud_security.cspm.exceptions import (
    CSPMEvaluationNotFoundError,
    CSPMFindingNotFoundError,
    CSPMPolicyNotFoundError,
    InvalidCSPMArgumentError,
)
from redforge.domain.cloud_security.cspm.finding import CSPMFinding
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import (
    CSPMEvaluationId,
    CSPMFindingId,
    CSPMPolicyId,
    FindingStatus,
)
from redforge.domain.cloud_security.exceptions import (
    CloudAccountNotFoundError,
    CloudAssetNotFoundError,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    OrganizationId,
)
from redforge.infrastructure.cloud_security.cspm.policy_loader import load_cspm_policies

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.cspm.repositories import (
        CSPMDriftBaselineRepository,
        CSPMEvaluationRepository,
        CSPMFindingRepository,
        CSPMPolicyRepository,
    )
    from redforge.domain.cloud_security.repositories import (
        CloudAccountRepository,
        CloudAssetRepository,
        CloudProviderRepository,
    )
    from redforge.infrastructure.cloud_security.acl.cspm_compliance_acl import (
        CSPMComplianceACL,
    )
    from redforge.infrastructure.cloud_security.acl.cspm_graph_acl import (
        CSPMFindingToGraphACL,
    )

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    RepoFactory = Callable[[AsyncSession], Any]


def _compliance_dtos(refs: list[Any]) -> list[ComplianceRefDTO]:
    return [
        ComplianceRefDTO(
            framework_key=r.framework_key,
            requirement_ref=r.requirement_ref,
            resolved=bool(getattr(r, "resolved", False)),
        )
        for r in refs
    ]


def _finding_dto(finding: CSPMFinding) -> CSPMFindingDTO:
    return CSPMFindingDTO(
        finding_id=str(finding.id),
        organization_id=str(finding.organization_id),
        cloud_asset_id=str(finding.cloud_asset_id),
        policy_id=str(finding.policy_id),
        rule_id=str(finding.rule_id),
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        title=finding.title,
        description=finding.description,
        status=finding.status.value,
        config_hash=finding.config_hash,
        fingerprint=finding.fingerprint,
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        detected_at=finding.detected_at,
        resolved_at=finding.resolved_at,
        reopened_at=finding.reopened_at,
        suppressed_until=finding.suppressed_until,
        accepted_by=finding.accepted_by,
        accepted_reason=finding.accepted_reason,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        version=finding.version,
        compliance_mapping=_compliance_dtos(finding.compliance_mapping),
        evidence=[
            FindingEvidenceDTO(
                evidence_id=e.evidence_id,
                path=e.path,
                expected=e.expected,
                actual=e.actual,
                message=e.message,
            )
            for e in finding.evidence
        ],
        remediation=finding.remediation.to_dict(),
    )


def _policy_dto(policy: CSPMPolicy) -> CSPMPolicyDTO:
    return CSPMPolicyDTO(
        policy_id=str(policy.id),
        rule_id=str(policy.rule_id),
        title=policy.title,
        description=policy.description,
        severity=policy.severity.value,
        version=str(policy.version),
        provider_types=list(policy.provider_types),
        asset_types=list(policy.asset_types),
        enabled=policy.enabled,
        evaluation_strategy=policy.evaluation_strategy,
        inherits_from=policy.inherits_from,
        metadata=policy.metadata.to_dict(),
        remediation=policy.remediation.to_dict(),
        compliance_mapping=_compliance_dtos(policy.compliance_mapping),
        rule=dict(policy.rule),
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


def _evaluation_dto(evaluation: CSPMEvaluation) -> CSPMEvaluationDTO:
    return CSPMEvaluationDTO(
        evaluation_id=str(evaluation.id),
        organization_id=str(evaluation.organization_id),
        cloud_account_id=evaluation.cloud_account_id,
        status=evaluation.status.value,
        assets_evaluated=evaluation.assets_evaluated,
        policies_evaluated=evaluation.policies_evaluated,
        findings_opened=evaluation.findings_opened,
        findings_resolved=evaluation.findings_resolved,
        diagnostics=dict(evaluation.diagnostics),
        started_at=evaluation.started_at,
        completed_at=evaluation.completed_at,
        error_message=evaluation.error_message,
        results=[
            EvaluationResultDTO(
                policy_id=r.policy_id,
                rule_id=r.rule_id,
                cloud_asset_id=r.cloud_asset_id,
                passed=r.passed,
                severity=r.severity,
                title=r.title,
                message=r.message,
                duration_ms=r.duration_ms,
            )
            for r in evaluation.results
        ],
    )


class CSPMAssessmentService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        policy_repo_factory: RepoFactory,
        finding_repo_factory: RepoFactory,
        evaluation_repo_factory: RepoFactory,
        drift_repo_factory: RepoFactory,
        asset_repo_factory: RepoFactory,
        account_repo_factory: RepoFactory,
        provider_repo_factory: RepoFactory,
        compliance_acl: CSPMComplianceACL | None = None,
        graph_acl: CSPMFindingToGraphACL | None = None,
        pipeline: EvaluationPipeline | None = None,
        snapshot_builder: ResourceSnapshotBuilder | None = None,
        context_factory: EvaluationContextFactory | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._policy_repo_factory = policy_repo_factory
        self._finding_repo_factory = finding_repo_factory
        self._evaluation_repo_factory = evaluation_repo_factory
        self._drift_repo_factory = drift_repo_factory
        self._asset_repo_factory = asset_repo_factory
        self._account_repo_factory = account_repo_factory
        self._provider_repo_factory = provider_repo_factory
        self._compliance_acl = compliance_acl
        self._graph_acl = graph_acl
        self._pipeline = pipeline or EvaluationPipeline()
        self._snapshot_builder = snapshot_builder or ResourceSnapshotBuilder()
        self._context_factory = context_factory or EvaluationContextFactory()
        self._policy_cache: list[CSPMPolicy] | None = None
        self._policies_synced = False

    def invalidate_policy_cache(self) -> None:
        self._policy_cache = None
        self._policies_synced = False

    async def _sync_policies_if_needed(self, policy_repo: CSPMPolicyRepository) -> None:
        if self._policies_synced and self._policy_cache is not None:
            return
        loaded = load_cspm_policies()
        await policy_repo.save_batch(loaded)
        self._policy_cache = loaded
        self._policies_synced = True

    async def _cached_policies(self, policy_repo: CSPMPolicyRepository) -> list[CSPMPolicy]:
        await self._sync_policies_if_needed(policy_repo)
        if self._policy_cache is None:
            self._policy_cache = await policy_repo.list_all()
        return list(self._policy_cache)

    async def _provider_type_for_account(
        self,
        *,
        account_id: CloudAccountId,
        org: OrganizationId,
        accounts: CloudAccountRepository,
        providers: CloudProviderRepository,
    ) -> str:
        account = await accounts.get_by_id(account_id, org)
        if account is None:
            raise CloudAccountNotFoundError(str(account_id))
        provider = await providers.get_by_id(account.cloud_provider_id, org)
        if provider is None:
            raise CloudAccountNotFoundError(str(account_id))
        return provider.provider_type.value

    async def _upsert_finding_from_violation(
        self,
        *,
        finding_repo: CSPMFindingRepository,
        policy: CSPMPolicy,
        org: OrganizationId,
        asset_id: CloudAssetId,
        config_hash: str,
        evidence: list[FindingEvidence],
        compliance_mapping: list[Any],
    ) -> tuple[CSPMFinding, bool]:
        fingerprint = CSPMFinding.build_fingerprint(
            str(policy.id), str(policy.rule_id), str(asset_id)
        )
        existing = await finding_repo.get_by_fingerprint(fingerprint, org)
        if existing is None:
            finding = CSPMFinding.open(
                cloud_asset_id=asset_id,
                organization_id=org,
                policy_id=policy.id,
                rule_id=policy.rule_id,
                severity=policy.severity,
                title=policy.title,
                description=policy.description,
                remediation=policy.remediation,
                compliance_mapping=list(compliance_mapping),
                evidence=evidence,
                config_hash=config_hash,
            )
            await finding_repo.save(finding)
            return finding, True

        if existing.status in {FindingStatus.RESOLVED, FindingStatus.EXPIRED}:
            existing.reopen(changed_by="system", reason="violation_redetected")
            existing.touch_seen(evidence=evidence, config_hash=config_hash)
            await finding_repo.save(existing)
            return existing, True

        if existing.status == FindingStatus.SUPPRESSED:
            existing.touch_seen(evidence=evidence, config_hash=config_hash)
            await finding_repo.save(existing)
            return existing, False

        existing.touch_seen(evidence=evidence, config_hash=config_hash)
        await finding_repo.save(existing)
        return existing, False

    async def _resolve_cleared_findings(
        self,
        *,
        finding_repo: CSPMFindingRepository,
        org: OrganizationId,
        asset_id: CloudAssetId,
        still_open_fingerprints: set[str],
    ) -> int:
        open_findings = await finding_repo.list_open_by_asset(asset_id, org)
        resolved = 0
        for finding in open_findings:
            if finding.fingerprint in still_open_fingerprints:
                continue
            finding.resolve(changed_by="system", reason="violation_cleared")
            await finding_repo.save(finding)
            resolved += 1
        return resolved

    async def evaluate_asset(self, command: EvaluateAssetCommand) -> CSPMEvaluationDTO:
        org = OrganizationId(command.organization_id)
        asset_id = CloudAssetId.from_string(command.cloud_asset_id)
        async with self._session_factory() as session, session.begin():
            policies_repo: CSPMPolicyRepository = self._policy_repo_factory(session)
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            evaluations_repo: CSPMEvaluationRepository = self._evaluation_repo_factory(session)
            drift_repo: CSPMDriftBaselineRepository = self._drift_repo_factory(session)
            assets: CloudAssetRepository = self._asset_repo_factory(session)
            accounts: CloudAccountRepository = self._account_repo_factory(session)
            providers: CloudProviderRepository = self._provider_repo_factory(session)

            asset = await assets.get_by_id(asset_id, org)
            if asset is None or asset.is_deleted:
                raise CloudAssetNotFoundError(command.cloud_asset_id)

            provider_type = await self._provider_type_for_account(
                account_id=asset.cloud_account_id,
                org=org,
                accounts=accounts,
                providers=providers,
            )
            policies = await self._cached_policies(policies_repo)
            context = self._context_factory.build(
                organization_id=str(org),
                evaluation_id="pending",
                triggered_by=command.triggered_by,
                cloud_account_id=str(asset.cloud_account_id),
                policy_ids=command.policy_ids,
            )
            evaluation = CSPMEvaluation.start(
                organization_id=org,
                context=context,
                cloud_account_id=str(asset.cloud_account_id),
            )
            # Fix context evaluation_id to match aggregate id
            evaluation.context = self._context_factory.build(
                organization_id=str(org),
                evaluation_id=str(evaluation.id),
                triggered_by=command.triggered_by,
                cloud_account_id=str(asset.cloud_account_id),
                policy_ids=command.policy_ids,
            )

            snapshot = self._snapshot_builder.build(asset, provider_type=provider_type)
            drift = DriftDetectionService(drift_repo)
            _baseline, drift_diag = await drift.ensure_baseline(snapshot=snapshot)

            try:
                pipeline_result = await self._pipeline.evaluate_snapshot(
                    snapshot=snapshot,
                    policies=policies,
                    policy_ids=command.policy_ids,
                )
                evaluation.append_results(pipeline_result.results)

                policy_by_id = {str(p.id): p for p in policies}
                opened = 0
                open_fps: set[str] = set()
                for result in pipeline_result.results:
                    if result.passed:
                        continue
                    policy = policy_by_id[result.policy_id]
                    compliance = list(policy.compliance_mapping)
                    if self._compliance_acl is not None:
                        compliance = await self._compliance_acl.resolve_refs(compliance)
                    finding, was_opened = await self._upsert_finding_from_violation(
                        finding_repo=findings_repo,
                        policy=policy,
                        org=org,
                        asset_id=asset_id,
                        config_hash=snapshot.config_hash,
                        evidence=list(result.evidence),
                        compliance_mapping=compliance,
                    )
                    open_fps.add(finding.fingerprint)
                    if was_opened:
                        opened += 1
                    if self._graph_acl is not None:
                        await self._graph_acl.project_finding(finding=finding, policy=policy)

                resolved = await self._resolve_cleared_findings(
                    finding_repo=findings_repo,
                    org=org,
                    asset_id=asset_id,
                    still_open_fingerprints=open_fps,
                )
                diagnostics = drift.diagnostics_to_dict([drift_diag])
                diagnostics["pipeline_duration_ms"] = pipeline_result.duration_ms
                evaluation.complete(
                    assets_evaluated=1,
                    policies_evaluated=pipeline_result.policies_evaluated,
                    findings_opened=opened,
                    findings_resolved=resolved,
                    diagnostics=diagnostics,
                )
            except Exception as exc:
                evaluation.fail(str(exc))
                await evaluations_repo.save(evaluation)
                raise

            await evaluations_repo.save(evaluation)
            evaluation.pop_events()
            return _evaluation_dto(evaluation)

    async def evaluate_account(
        self, command: TriggerCSPMEvaluationCommand
    ) -> CSPMEvaluationDTO:
        if not command.cloud_account_id:
            raise InvalidCSPMArgumentError("cloud_account_id", "required for account evaluation")
        org = OrganizationId(command.organization_id)
        account_id = CloudAccountId.from_string(command.cloud_account_id)

        async with self._session_factory() as session, session.begin():
            policies_repo: CSPMPolicyRepository = self._policy_repo_factory(session)
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            evaluations_repo: CSPMEvaluationRepository = self._evaluation_repo_factory(session)
            drift_repo: CSPMDriftBaselineRepository = self._drift_repo_factory(session)
            assets: CloudAssetRepository = self._asset_repo_factory(session)
            accounts: CloudAccountRepository = self._account_repo_factory(session)
            providers: CloudProviderRepository = self._provider_repo_factory(session)

            provider_type = await self._provider_type_for_account(
                account_id=account_id,
                org=org,
                accounts=accounts,
                providers=providers,
            )
            policies = await self._cached_policies(policies_repo)
            evaluation = CSPMEvaluation.start(
                organization_id=org,
                context=self._context_factory.build(
                    organization_id=str(org),
                    evaluation_id="pending",
                    triggered_by=command.triggered_by,
                    cloud_account_id=command.cloud_account_id,
                    incremental=command.incremental,
                    policy_ids=command.policy_ids,
                ),
                cloud_account_id=command.cloud_account_id,
            )
            evaluation.context = self._context_factory.build(
                organization_id=str(org),
                evaluation_id=str(evaluation.id),
                triggered_by=command.triggered_by,
                cloud_account_id=command.cloud_account_id,
                incremental=command.incremental,
                policy_ids=command.policy_ids,
            )

            drift = DriftDetectionService(drift_repo)
            drift_diags = []
            assets_evaluated = 0
            policies_evaluated = 0
            findings_opened = 0
            findings_resolved = 0
            page = 1
            try:
                while True:
                    page_result = await assets.list_by_account(
                        account_id,
                        org,
                        None,
                        page=page,
                        size=100,
                        include_deleted=False,
                    )
                    if not page_result.items:
                        break
                    for asset in page_result.items:
                        snapshot = self._snapshot_builder.build(
                            asset, provider_type=provider_type
                        )
                        _b, diag = await drift.ensure_baseline(snapshot=snapshot)
                        drift_diags.append(diag)
                        pipeline_result = await self._pipeline.evaluate_snapshot(
                            snapshot=snapshot,
                            policies=policies,
                            policy_ids=command.policy_ids,
                        )
                        evaluation.append_results(pipeline_result.results)
                        assets_evaluated += 1
                        policies_evaluated += pipeline_result.policies_evaluated
                        policy_by_id = {str(p.id): p for p in policies}
                        open_fps: set[str] = set()
                        for result in pipeline_result.results:
                            if result.passed:
                                continue
                            policy = policy_by_id[result.policy_id]
                            compliance = list(policy.compliance_mapping)
                            if self._compliance_acl is not None:
                                compliance = await self._compliance_acl.resolve_refs(
                                    compliance
                                )
                            finding, was_opened = await self._upsert_finding_from_violation(
                                finding_repo=findings_repo,
                                policy=policy,
                                org=org,
                                asset_id=asset.id,
                                config_hash=snapshot.config_hash,
                                evidence=list(result.evidence),
                                compliance_mapping=compliance,
                            )
                            open_fps.add(finding.fingerprint)
                            if was_opened:
                                findings_opened += 1
                            if self._graph_acl is not None:
                                await self._graph_acl.project_finding(
                                    finding=finding, policy=policy
                                )
                        findings_resolved += await self._resolve_cleared_findings(
                            finding_repo=findings_repo,
                            org=org,
                            asset_id=asset.id,
                            still_open_fingerprints=open_fps,
                        )
                    if page * 100 >= page_result.total:
                        break
                    page += 1

                diagnostics = drift.diagnostics_to_dict(drift_diags)
                evaluation.complete(
                    assets_evaluated=assets_evaluated,
                    policies_evaluated=policies_evaluated,
                    findings_opened=findings_opened,
                    findings_resolved=findings_resolved,
                    diagnostics=diagnostics,
                )
            except Exception as exc:
                evaluation.fail(str(exc))
                await evaluations_repo.save(evaluation)
                raise

            await evaluations_repo.save(evaluation)
            evaluation.pop_events()
            return _evaluation_dto(evaluation)

    async def trigger_evaluation(
        self, command: TriggerCSPMEvaluationCommand
    ) -> CSPMEvaluationDTO:
        if command.cloud_account_id:
            return await self.evaluate_account(command)
        # Org-wide: iterate accounts
        org = OrganizationId(command.organization_id)
        async with self._session_factory() as session:
            accounts: CloudAccountRepository = self._account_repo_factory(session)
            page = await accounts.list_by_organization(org, page=1, size=200)
        last: CSPMEvaluationDTO | None = None
        for account in page.items:
            last = await self.evaluate_account(
                TriggerCSPMEvaluationCommand(
                    organization_id=command.organization_id,
                    cloud_account_id=str(account.id),
                    triggered_by=command.triggered_by,
                    policy_ids=command.policy_ids,
                    incremental=command.incremental,
                )
            )
        if last is None:
            async with self._session_factory() as session, session.begin():
                evaluations_repo: CSPMEvaluationRepository = self._evaluation_repo_factory(
                    session
                )
                evaluation = CSPMEvaluation.start(
                    organization_id=org,
                    context=self._context_factory.build(
                        organization_id=str(org),
                        evaluation_id="pending",
                        triggered_by=command.triggered_by,
                        policy_ids=command.policy_ids,
                        incremental=command.incremental,
                    ),
                )
                evaluation.context = self._context_factory.build(
                    organization_id=str(org),
                    evaluation_id=str(evaluation.id),
                    triggered_by=command.triggered_by,
                    policy_ids=command.policy_ids,
                    incremental=command.incremental,
                )
                evaluation.complete(
                    assets_evaluated=0,
                    policies_evaluated=0,
                    findings_opened=0,
                    findings_resolved=0,
                    diagnostics={"message": "no_accounts"},
                )
                await evaluations_repo.save(evaluation)
                return _evaluation_dto(evaluation)
        return last

    async def update_finding_status(
        self, command: UpdateFindingStatusCommand
    ) -> CSPMFindingDTO:
        org = OrganizationId(command.organization_id)
        finding_id = CSPMFindingId.from_string(command.finding_id)
        try:
            target = FindingStatus(command.status.upper())
        except ValueError as exc:
            raise InvalidCSPMArgumentError("status", f"invalid: {command.status}") from exc

        async with self._session_factory() as session, session.begin():
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            finding = await findings_repo.get_by_id(finding_id, org)
            if finding is None:
                raise CSPMFindingNotFoundError(command.finding_id)

            if target is FindingStatus.CONFIRMED:
                finding.confirm(changed_by=command.changed_by, reason=command.reason)
            elif target is FindingStatus.SUPPRESSED:
                finding.suppress(
                    changed_by=command.changed_by,
                    reason=command.reason or "suppressed",
                    until=command.suppressed_until,
                )
            elif target is FindingStatus.ACCEPTED_RISK:
                finding.accept_risk(
                    accepted_by=command.accepted_by or command.changed_by,
                    reason=command.reason or "accepted",
                )
            elif target is FindingStatus.RESOLVED:
                finding.resolve(changed_by=command.changed_by, reason=command.reason or "resolved")
            elif target is FindingStatus.REOPENED:
                finding.reopen(changed_by=command.changed_by, reason=command.reason or "reopened")
            elif target is FindingStatus.EXPIRED:
                finding.expire(changed_by=command.changed_by)
            elif target is FindingStatus.OPEN:
                finding._transition(
                    FindingStatus.OPEN,
                    changed_by=command.changed_by,
                    reason=command.reason or "reopened_to_open",
                )
            else:
                raise InvalidCSPMArgumentError("status", f"unsupported: {target.value}")

            await findings_repo.save(finding)
            finding.pop_events()
            return _finding_dto(finding)

    async def list_findings(self, query: ListFindingsQuery) -> CSPMFindingPageDTO:
        org = OrganizationId(query.organization_id)
        status = FindingStatus(query.status.upper()) if query.status else None
        asset_id = (
            CloudAssetId.from_string(query.cloud_asset_id) if query.cloud_asset_id else None
        )
        async with self._session_factory() as session:
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            page = await findings_repo.list_by_organization(
                org,
                page=query.page,
                size=query.size,
                status=status,
                cloud_asset_id=asset_id,
                severity=query.severity,
            )
            return CSPMFindingPageDTO(
                items=[_finding_dto(i) for i in page.items],
                page=page.page,
                size=page.size,
                total=page.total,
            )

    async def get_finding(self, query: GetFindingQuery) -> CSPMFindingDTO:
        org = OrganizationId(query.organization_id)
        finding_id = CSPMFindingId.from_string(query.finding_id)
        async with self._session_factory() as session:
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            finding = await findings_repo.get_by_id(finding_id, org)
            if finding is None:
                raise CSPMFindingNotFoundError(query.finding_id)
            return _finding_dto(finding)

    async def list_policies(self, query: ListPoliciesQuery) -> list[CSPMPolicyDTO]:
        async with self._session_factory() as session, session.begin():
            policies_repo: CSPMPolicyRepository = self._policy_repo_factory(session)
            await self._sync_policies_if_needed(policies_repo)
            policies = (
                await policies_repo.list_enabled()
                if query.enabled_only
                else await policies_repo.list_all()
            )
            self._policy_cache = await policies_repo.list_all()
            return [_policy_dto(p) for p in policies]

    async def get_policy(self, query: GetPolicyQuery) -> CSPMPolicyDTO:
        async with self._session_factory() as session, session.begin():
            policies_repo: CSPMPolicyRepository = self._policy_repo_factory(session)
            await self._sync_policies_if_needed(policies_repo)
            policy = await policies_repo.get_by_id(CSPMPolicyId(query.policy_id))
            if policy is None:
                raise CSPMPolicyNotFoundError(query.policy_id)
            return _policy_dto(policy)

    async def list_evaluations(self, query: ListEvaluationsQuery) -> CSPMEvaluationPageDTO:
        org = OrganizationId(query.organization_id)
        async with self._session_factory() as session:
            evaluations_repo: CSPMEvaluationRepository = self._evaluation_repo_factory(session)
            page = await evaluations_repo.list_by_organization(
                org, page=query.page, size=query.size
            )
            return CSPMEvaluationPageDTO(
                items=[_evaluation_dto(i) for i in page.items],
                page=page.page,
                size=page.size,
                total=page.total,
            )

    async def get_evaluation(self, query: GetEvaluationQuery) -> CSPMEvaluationDTO:
        org = OrganizationId(query.organization_id)
        evaluation_id = CSPMEvaluationId.from_string(query.evaluation_id)
        async with self._session_factory() as session:
            evaluations_repo: CSPMEvaluationRepository = self._evaluation_repo_factory(session)
            evaluation = await evaluations_repo.get_by_id(evaluation_id, org)
            if evaluation is None:
                raise CSPMEvaluationNotFoundError(query.evaluation_id)
            return _evaluation_dto(evaluation)

    async def finding_summary(self, query: SummaryQuery) -> FindingSummaryDTO:
        org = OrganizationId(query.organization_id)
        async with self._session_factory() as session:
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            by_severity = await findings_repo.count_open_by_severity(org)
            return FindingSummaryDTO(
                organization_id=str(org),
                open_by_severity=by_severity,
                total_open=sum(by_severity.values()),
            )

    async def compliance_summary(self, query: SummaryQuery) -> ComplianceSummaryDTO:
        org = OrganizationId(query.organization_id)
        async with self._session_factory() as session, session.begin():
            findings_repo: CSPMFindingRepository = self._finding_repo_factory(session)
            policies_repo: CSPMPolicyRepository = self._policy_repo_factory(session)
            await self._sync_policies_if_needed(policies_repo)
            policies = await policies_repo.list_enabled()
            frameworks: set[str] = set()
            controls = 0
            unresolved = 0
            for policy in policies:
                refs = policy.compliance_mapping
                if self._compliance_acl is not None:
                    refs = await self._compliance_acl.resolve_refs(list(refs))
                for ref in refs:
                    frameworks.add(ref.framework_key)
                    controls += 1
                    if not ref.resolved:
                        unresolved += 1
            page = await findings_repo.list_by_organization(org, page=1, size=200)
            open_mapped = sum(
                1
                for f in page.items
                if f.status
                in {FindingStatus.OPEN, FindingStatus.CONFIRMED, FindingStatus.REOPENED}
                and f.compliance_mapping
            )
            return ComplianceSummaryDTO(
                organization_id=str(org),
                mapped_frameworks=sorted(frameworks),
                mapped_controls=controls,
                unresolved_refs=unresolved,
                open_findings_with_mapping=open_mapped,
            )

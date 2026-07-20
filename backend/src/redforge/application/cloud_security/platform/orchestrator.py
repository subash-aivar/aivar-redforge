"""Cloud platform orchestrator - sequences Phases 1-7 without duplicating logic."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from redforge.application.cloud_security.cspm.dtos import TriggerCSPMEvaluationCommand
from redforge.application.cloud_security.discovery_dtos import TriggerAssetDiscoveryCommand
from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountPageDTO,
    ListCloudAccountsQuery,
)
from redforge.application.cloud_security.identity_dtos import TriggerIdentityDiscoveryCommand
from redforge.application.cloud_security.kubernetes.dtos import DiscoverClusterCommand
from redforge.application.cloud_security.platform.dtos import (
    OrchestratePlatformCommand,
    OrchestrationRunDTO,
    StepResultDTO,
)
from redforge.application.cloud_security.platform.observability import (
    bind_run_context,
    log_step,
    new_operation_id,
    step_timer,
)
from redforge.application.cloud_security.risk.dtos import CalculateRiskCommand
from redforge.application.cloud_security.runtime.dtos import IngestRuntimeEventsCommand
from redforge.domain.cloud_security.platform.entities import (
    OrchestrationRun,
    OrchestrationStepResult,
)
from redforge.domain.cloud_security.platform.exceptions import (
    InvalidPlatformArgumentError,
    PlatformOrchestrationError,
)
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationScope,
    StepName,
    StepStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


class _AssetDiscoveryPort(Protocol):
    async def discover_account(self, command: TriggerAssetDiscoveryCommand) -> Any: ...


class _IdentityDiscoveryPort(Protocol):
    async def discover_account(self, command: TriggerIdentityDiscoveryCommand) -> Any: ...


class _CSPMPort(Protocol):
    async def trigger_evaluation(self, command: TriggerCSPMEvaluationCommand) -> Any: ...


class _K8sPort(Protocol):
    async def discover_cluster(self, command: DiscoverClusterCommand) -> Any: ...

    async def list_clusters(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[Any]: ...


class _RuntimeIngestPort(Protocol):
    async def ingest(self, command: IngestRuntimeEventsCommand) -> Any: ...


class _RiskPort(Protocol):
    async def calculate(self, command: CalculateRiskCommand) -> Any: ...


class _FoundationPort(Protocol):
    async def list_cloud_accounts(self, query: ListCloudAccountsQuery) -> CloudAccountPageDTO: ...


def _run_to_dto(run: OrchestrationRun) -> OrchestrationRunDTO:
    return OrchestrationRunDTO(
        run_id=str(run.id),
        organization_id=str(run.organization_id),
        scope=run.scope.value,
        target_id=run.target_id,
        status=run.status.value,
        steps=[
            StepResultDTO(
                step_name=s.step_name.value,
                status=s.status.value,
                started_at=s.started_at,
                completed_at=s.completed_at,
                duration_ms=s.duration_ms,
                message=s.message,
                error=s.error,
                details=dict(s.details),
            )
            for s in run.steps
        ],
        diagnostics=dict(run.diagnostics),
        operation_id=run.operation_id,
        correlation_id=run.correlation_id,
        request_id=run.request_id,
        started_at=run.started_at,
        completed_at=run.completed_at,
        row_version=run.row_version,
    )


class CloudPlatformOrchestrator:
    """Runs the Phase 1-7 pipeline by calling injected existing services only."""

    def __init__(
        self,
        *,
        foundation: _FoundationPort | None = None,
        asset_discovery: _AssetDiscoveryPort | None = None,
        identity_discovery: _IdentityDiscoveryPort | None = None,
        cspm: _CSPMPort | None = None,
        kubernetes: _K8sPort | None = None,
        runtime_ingestion: _RuntimeIngestPort | None = None,
        risk: _RiskPort | None = None,
        session_factory: Any | None = None,
        run_repo_factory: Any | None = None,
    ) -> None:
        self._foundation = foundation
        self._asset_discovery = asset_discovery
        self._identity_discovery = identity_discovery
        self._cspm = cspm
        self._kubernetes = kubernetes
        self._runtime_ingestion = runtime_ingestion
        self._risk = risk
        self._session_factory = session_factory
        self._run_repo_factory = run_repo_factory

    async def orchestrate(self, command: OrchestratePlatformCommand) -> OrchestrationRunDTO:
        if not command.organization_wide and command.cloud_account_id is None:
            raise InvalidPlatformArgumentError(
                "cloud_account_id",
                "required unless organization_wide=True",
            )

        operation_id = new_operation_id()
        if command.organization_wide and command.cloud_account_id is None:
            scope = OrchestrationScope.ORGANIZATION
            target_id = command.organization_id
            account_ids = await self._resolve_account_ids(command.organization_id)
        else:
            assert command.cloud_account_id is not None
            scope = OrchestrationScope.ACCOUNT
            target_id = str(command.cloud_account_id)
            account_ids = [command.cloud_account_id]

        run = OrchestrationRun.start(
            organization_id=OrganizationId(command.organization_id),
            scope=scope,
            target_id=target_id,
            operation_id=operation_id,
            correlation_id=command.correlation_id,
            request_id=command.request_id,
        )
        bind_run_context(
            organization_id=command.organization_id,
            operation_id=operation_id,
            run_id=str(run.id),
            correlation_id=command.correlation_id,
            request_id=command.request_id,
        )
        run.diagnostics["account_ids"] = [str(a) for a in account_ids]
        run.diagnostics["include_k8s"] = command.include_k8s
        run.diagnostics["include_runtime"] = command.include_runtime
        run.diagnostics["fail_fast"] = command.fail_fast

        abort = False
        for account_id in account_ids:
            if abort:
                break
            abort = await self._run_account_pipeline(
                run,
                organization_id=command.organization_id,
                account_id=account_id,
                command=command,
            )

        if abort and command.fail_fast:
            run.fail("fail_fast aborted pipeline")
        else:
            run.complete()

        await self._persist(run)
        run.pop_events()
        return _run_to_dto(run)

    async def _resolve_account_ids(self, organization_id: str) -> list[UUID]:
        if self._foundation is None:
            raise PlatformOrchestrationError("foundation service required for organization-wide")
        page = await self._foundation.list_cloud_accounts(
            ListCloudAccountsQuery(organization_id=organization_id, page=1, size=200)
        )
        ids: list[UUID] = []
        for acct in page.items:
            try:
                ids.append(UUID(acct.account_id))
            except ValueError:
                continue
        if not ids:
            raise InvalidPlatformArgumentError(
                "organization_wide", "no cloud accounts registered"
            )
        return ids

    async def _run_account_pipeline(
        self,
        run: OrchestrationRun,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> bool:
        """Execute per-account steps. Returns True if fail_fast should abort."""
        steps: list[tuple[StepName, Any]] = [
            (StepName.DISCOVER_ASSETS, self._step_discover_assets),
            (StepName.DISCOVER_IDENTITY, self._step_discover_identity),
            (StepName.EVALUATE_CSPM, self._step_evaluate_cspm),
        ]
        if command.include_k8s:
            steps.append((StepName.DISCOVER_KUBERNETES, self._step_discover_k8s))
        else:
            self._record_skipped(run, StepName.DISCOVER_KUBERNETES, "include_k8s=false")
        if command.include_runtime:
            steps.append((StepName.INGEST_RUNTIME, self._step_ingest_runtime))
        else:
            self._record_skipped(run, StepName.INGEST_RUNTIME, "include_runtime=false")
        steps.append((StepName.CALCULATE_RISK, self._step_calculate_risk))

        for step_name, handler in steps:
            started = datetime.now(UTC)
            with step_timer(step_name.value) as meta:
                try:
                    details = await handler(
                        organization_id=organization_id,
                        account_id=account_id,
                        command=command,
                    )
                    result = OrchestrationStepResult(
                        step_name=step_name,
                        status=StepStatus.COMPLETED,
                        started_at=started,
                        completed_at=datetime.now(UTC),
                        duration_ms=float(meta["duration_ms"]),
                        message="ok",
                        details={
                            **(details or {}),
                            "cloud_account_id": str(account_id),
                        },
                    )
                    run.record_step(result)
                    log_step(
                        step_name=step_name.value,
                        status=StepStatus.COMPLETED.value,
                        operation_id=run.operation_id,
                        duration_ms=result.duration_ms,
                    )
                except Exception as exc:
                    err = f"{type(exc).__name__}: {exc}"[:2000]
                    run.fail_step(
                        step_name,
                        err,
                        started_at=started,
                        duration_ms=float(meta["duration_ms"]),
                        details={"cloud_account_id": str(account_id)},
                    )
                    log_step(
                        step_name=step_name.value,
                        status=StepStatus.FAILED.value,
                        operation_id=run.operation_id,
                        duration_ms=float(meta["duration_ms"]),
                        error=err,
                    )
                    if command.fail_fast:
                        return True
        return False

    def _record_skipped(self, run: OrchestrationRun, step_name: StepName, reason: str) -> None:
        now = datetime.now(UTC)
        run.record_step(
            OrchestrationStepResult(
                step_name=step_name,
                status=StepStatus.SKIPPED,
                started_at=now,
                completed_at=now,
                duration_ms=0.0,
                message=reason,
            )
        )

    async def _step_discover_assets(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> dict[str, Any]:
        if self._asset_discovery is None:
            raise PlatformOrchestrationError("asset discovery service not configured")
        result = await self._asset_discovery.discover_account(
            TriggerAssetDiscoveryCommand(
                organization_id=organization_id,
                cloud_account_id=str(account_id),
            )
        )
        return {
            "discovered_count": getattr(result, "discovered_count", None),
            "sync_status": getattr(result, "sync_status", None),
        }

    async def _step_discover_identity(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> dict[str, Any]:
        if self._identity_discovery is None:
            raise PlatformOrchestrationError("identity discovery service not configured")
        result = await self._identity_discovery.discover_account(
            TriggerIdentityDiscoveryCommand(
                organization_id=organization_id,
                cloud_account_id=str(account_id),
            )
        )
        return {
            "discovered_count": getattr(result, "discovered_count", None),
            "sync_status": getattr(result, "sync_status", None),
        }

    async def _step_evaluate_cspm(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> dict[str, Any]:
        if self._cspm is None:
            raise PlatformOrchestrationError("CSPM assessment service not configured")
        result = await self._cspm.trigger_evaluation(
            TriggerCSPMEvaluationCommand(
                organization_id=organization_id,
                cloud_account_id=str(account_id),
                triggered_by="platform_orchestrator",
            )
        )
        return {
            "evaluation_id": getattr(result, "evaluation_id", None)
            or getattr(result, "id", None),
            "status": getattr(result, "status", None),
            "findings_opened": getattr(result, "findings_opened", None),
        }

    async def _step_discover_k8s(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> dict[str, Any]:
        if self._kubernetes is None:
            raise PlatformOrchestrationError("kubernetes security service not configured")
        result = await self._kubernetes.discover_cluster(
            DiscoverClusterCommand(
                organization_id=organization_id,
                cloud_account_id=account_id,
                cloud_asset_id=command.cloud_asset_id,
            )
        )
        return {
            "cluster_id": str(getattr(result, "cluster_id", getattr(result, "id", ""))),
        }

    async def _step_ingest_runtime(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> dict[str, Any]:
        if self._runtime_ingestion is None:
            raise PlatformOrchestrationError("runtime ingestion service not configured")
        events = list(command.runtime_events or [])
        result = await self._runtime_ingestion.ingest(
            IngestRuntimeEventsCommand(
                organization_id=organization_id,
                cloud_account_id=account_id,
                events=events,
                source="platform_orchestrator",
            )
        )
        return {
            "accepted": getattr(result, "accepted", None),
            "rejected": getattr(result, "rejected", None),
            "event_count": len(events),
        }

    async def _step_calculate_risk(
        self,
        *,
        organization_id: str,
        account_id: UUID,
        command: OrchestratePlatformCommand,
    ) -> dict[str, Any]:
        if self._risk is None:
            raise PlatformOrchestrationError("risk calculation service not configured")
        result = await self._risk.calculate(
            CalculateRiskCommand(
                organization_id=organization_id,
                account_id=account_id,
                organization_wide=False,
            )
        )
        return {
            "assessment_id": getattr(result, "assessment_id", None),
            "assets_evaluated": getattr(result, "assets_evaluated", None),
            "status": getattr(result, "status", None),
        }

    async def _persist(self, run: OrchestrationRun) -> None:
        if self._session_factory is None or self._run_repo_factory is None:
            return
        async with self._session_factory() as session, session.begin():
            repo = self._run_repo_factory(session)
            await repo.save(run)

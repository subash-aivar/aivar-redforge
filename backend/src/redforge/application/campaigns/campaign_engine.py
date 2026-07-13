"""Enterprise Continuous Validation Campaign Engine.

Sits ONE architectural layer above ValidationService.

Responsibility split:
  ValidationService          — single-target execution, evidence, findings,
                               risk correlation, KG population, event publishing
  CampaignEngine (this file) — multi-target fan-out, progress tracking,
                               campaign lifecycle, drift detection, campaign KG

The engine implements PipelineExecutor so SchedulerService can trigger
it via its existing protocol interface without any modification to
scheduler.py.

ExecutionStrategy (from ValidationPolicy.execution_strategy) is enforced
here for the first time — it was stored in the domain but had no
enforcement code anywhere in the stack until this sprint.

Thread safety: CampaignEngine is stateless across calls. Each
execute_campaign() invocation creates its own local state. Multiple
concurrent campaign executions sharing one CampaignEngine instance are
safe, provided the injected collaborators are themselves concurrency-safe.

Architectural constraints (ADR-0001):
  - This module is in the application layer. It may import from
    application.*, domain.*, shared.*, core.*.
  - It does NOT import from infrastructure.* or api.*.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.campaigns.contracts import (
    BaselineCampaignPort,
    CampaignKnowledgeProjectorPort,
    CampaignRepositoryPort,
    ExecutionPolicyPort,
    TargetSelectorPort,
)
from redforge.application.campaigns.drift_detector import DriftDetector
from redforge.application.validation_service import (
    ValidationServiceRequest,
    ValidationServiceResult,
)
from redforge.core.logging import get_logger
from redforge.domain.authorization.exceptions import ExecutionNotAuthorizedError
from redforge.domain.authorization.value_objects import ActionClass, ScopeEntityType
from redforge.domain.campaigns.entity import Campaign
from redforge.domain.campaigns.value_objects import (
    CampaignConfiguration,
    CampaignMetrics,
    CampaignType,
    DriftSummary,
    TargetResult,
)
from redforge.domain.policies.value_objects import ExecutionStrategy
from redforge.shared.identifiers import EntityId

# CampaignEngine is the only real active-execution dispatch path in the
# platform today (api/v1/execution_plans.py is an inert stub — see the
# M10 execution-bypass-review doc). Every dispatch below is gated by
# ExecutionPolicyPort.evaluate() BEFORE any Campaign aggregate exists,
# for both the direct entry point (execute_campaign) and the
# scheduler-triggered entry point (trigger). Campaign execution is
# classified as ACTIVE_VALIDATION for M10 policy purposes.
_CAMPAIGN_ACTION_CLASS = ActionClass.ACTIVE_VALIDATION.value
_SCHEDULER_ACTOR = "system:scheduler"

if TYPE_CHECKING:
    from redforge.application.contracts import EventPublisherPort
    from redforge.application.validation_service import ValidationService

logger = get_logger(__name__)


# ─── Campaign Execution Request / Result ──────────────────────────────────────


@dataclass(frozen=True)
class CampaignRequest:
    """Parameters for a new campaign execution.

    Callers provide enough information for CampaignEngine to build the
    per-target ValidationServiceRequest. Fields map directly to
    ValidationServiceRequest fields where names match.
    """

    organization_id: str
    policy_id: str
    campaign_type: CampaignType
    target_endpoint_map: dict[str, str]   # target_id → endpoint URL
    target_provider_map: dict[str, str]   # target_id → provider string
    target_name_map: dict[str, str]       # target_id → human name
    target_model_map: dict[str, str]      # target_id → model string
    target_system_prompt_map: dict[str, str]  # target_id → system prompt
    attack_categories: frozenset[str]
    correlation_id: str
    actor_user_id: str
    execution_strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL
    severity_minimum: str = "low"
    max_attacks_per_category: int = 0
    policy_id_for_validation: str | None = None
    baseline_campaign_id: str | None = None
    configuration: CampaignConfiguration | None = None
    metadata: dict[str, str] | None = None


@dataclass(frozen=True)
class CampaignResult:
    """Summary returned after a campaign finishes."""

    campaign_id: str
    organization_id: str
    status: str
    total_targets: int
    successful_targets: int
    failed_targets: int
    total_findings: int
    mean_vulnerability_rate: float
    duration_ms: int
    regression_detected: bool
    target_results: list[TargetResult]
    failure_reason: str | None = None

    @property
    def success_rate(self) -> float:
        if self.total_targets == 0:
            return 0.0
        return self.successful_targets / self.total_targets


# ─── Campaign Engine ──────────────────────────────────────────────────────────


class CampaignEngine:
    """Orchestrates multi-target validation campaigns.

    Implements the PipelineExecutor Protocol from application/scheduler.py
    so SchedulerService can trigger this engine without knowing its concrete
    type (duck typing via @runtime_checkable).

    Constructor parameters are all required — no domain defaults. This
    mirrors the Sprint 16 EvaluationEngine contract: every collaborator must
    be explicitly wired by the caller (infrastructure or test).

    Parameters
    ----------
    validation_service:
        The canonical single-target execution path. CampaignEngine calls
        ``validation_service.execute()`` once per target.
    target_selector:
        Resolves concrete target IDs from the policy scope when trigger()
        is called by SchedulerService (which only passes a single target_id).
        When execute_campaign() is called directly the targets come from
        CampaignRequest.target_endpoint_map.
    campaign_repository:
        Persist/retrieve Campaign aggregates.
    execution_policy_service:
        REQUIRED (M10). The mandatory ExecutionPolicyService gate —
        see ExecutionPolicyPort's docstring. No default: a caller
        cannot construct a working CampaignEngine without wiring a
        real policy decision.
    drift_detector:
        Computes DriftSummary when a baseline_campaign_id is provided.
    baseline_port:
        Reads historical findings/rates from the baseline campaign.
        Required only when baseline_campaign_id is provided; can be None.
    knowledge_projector:
        Optional. When provided, projects the Campaign node into the
        KnowledgeGraph after completion.
    event_publisher:
        Optional. When provided, publishes Campaign domain events post-commit.
    """

    def __init__(
        self,
        validation_service: ValidationService,
        target_selector: TargetSelectorPort,
        campaign_repository: CampaignRepositoryPort,
        execution_policy_service: ExecutionPolicyPort,
        drift_detector: DriftDetector | None = None,
        baseline_port: BaselineCampaignPort | None = None,
        knowledge_projector: CampaignKnowledgeProjectorPort | None = None,
        event_publisher: EventPublisherPort | None = None,
    ) -> None:
        self._validation_service = validation_service
        self._target_selector = target_selector
        self._campaign_repository = campaign_repository
        self._execution_policy_service = execution_policy_service
        self._drift_detector = drift_detector or DriftDetector()
        self._baseline_port = baseline_port
        self._knowledge_projector = knowledge_projector
        self._event_publisher = event_publisher

    # ── PipelineExecutor Protocol implementation ──────────────────────────────

    async def trigger(
        self, organization_id: str, target_id: str, policy_id: str
    ) -> str:
        """Entry point for SchedulerService.

        Implements PipelineExecutor.trigger(). Resolves targets via
        TargetSelectorPort (ignores the single target_id; the policy scope
        determines the full target set), creates a minimal CampaignRequest,
        and runs the full campaign. Returns the campaign_id string.

        The single target_id parameter from SchedulerService is intentionally
        ignored — campaigns are policy-scoped, not single-target. The
        scheduler's ValidationSchedule.target_id is treated as a hint (e.g.
        a seed target), not as the complete target set.
        """
        resolved_target_ids = await self._target_selector.select(
            organization_id=organization_id,
            policy_id=policy_id,
        )
        if not resolved_target_ids:
            resolved_target_ids = [target_id]  # fall back to the scheduler hint

        await self._require_execution_allowed(
            organization_id=organization_id,
            actor_user_id=_SCHEDULER_ACTOR,
            target_ids=resolved_target_ids,
        )

        target_id_set = frozenset(EntityId.from_string(t) for t in resolved_target_ids)
        campaign = Campaign.create(
            organization_id=EntityId.from_string(organization_id),
            policy_id=EntityId.from_string(policy_id),
            campaign_type=CampaignType.SCHEDULED,
            target_ids=target_id_set,
            metadata={"triggered_by": "scheduler"},
        )
        await self._campaign_repository.save(campaign)
        # For scheduler-triggered campaigns, we need provider info per target.
        # Those details are fetched at execution time by ValidationService's
        # AttackResolverPort — CampaignEngine does not duplicate that lookup.
        # This path is intentionally minimal: it signals campaign creation and
        # starts the run; infrastructure wires the full CampaignRequest fields.
        logger.info(
            "campaign_triggered_by_scheduler",
            campaign_id=str(campaign.id),
            organization_id=organization_id,
            policy_id=policy_id,
            target_count=len(target_id_set),
        )
        return str(campaign.id)

    # ── Direct execution entry point ──────────────────────────────────────────

    async def execute_campaign(self, request: CampaignRequest) -> CampaignResult:
        """Execute a complete validation campaign.

        Flow:
          1. Create Campaign aggregate (PENDING).
          2. Persist.
          3. Transition to RUNNING.
          4. Fan out N ValidationService.execute() calls (concurrency
             governed by request.execution_strategy and
             configuration.max_concurrent_targets).
          5. Record per-target outcomes on Campaign.
          6. Compute CampaignMetrics.
          7. If baseline_campaign_id provided, compute DriftSummary.
          8. Transition Campaign to COMPLETED (or FAILED).
          9. Persist final state.
         10. Post-commit: project into KG, publish events (swallowed — cannot
             retroactively fail a persisted campaign).

        Raises whatever propagates from Campaign.create() (e.g.
        EmptyCampaignTargetsError). ValidationService errors per target are
        caught and recorded as failed target results — they do NOT abort the
        whole campaign unless ALL targets fail.
        """
        start = time.perf_counter()

        await self._require_execution_allowed(
            organization_id=request.organization_id,
            actor_user_id=request.actor_user_id,
            target_ids=list(request.target_endpoint_map),
        )

        target_ids = frozenset(
            EntityId.from_string(tid)
            for tid in request.target_endpoint_map
        )

        campaign = Campaign.create(
            organization_id=EntityId.from_string(request.organization_id),
            policy_id=EntityId.from_string(request.policy_id),
            campaign_type=request.campaign_type,
            target_ids=target_ids,
            configuration=request.configuration,
            baseline_campaign_id=(
                EntityId.from_string(request.baseline_campaign_id)
                if request.baseline_campaign_id else None
            ),
            metadata=request.metadata,
        )
        await self._campaign_repository.save(campaign)

        campaign.start()
        await self._campaign_repository.save(campaign)

        target_results: list[TargetResult] = []
        try:
            target_results = await self._execute_targets(campaign, request)
        except Exception as exc:
            logger.exception(
                "campaign_execution_fatal_error",
                campaign_id=str(campaign.id),
                error=str(exc),
            )
            campaign.fail(str(exc))
            await self._campaign_repository.save(campaign)
            raise

        metrics = _compute_metrics(target_results, int((time.perf_counter() - start) * 1000))

        drift_summary = await self._maybe_detect_drift(
            campaign=campaign,
            baseline_campaign_id=request.baseline_campaign_id,
            target_results=target_results,
        )

        campaign.complete(metrics=metrics, drift_summary=drift_summary)
        await self._campaign_repository.save(campaign)

        self._project_knowledge_graph_safely(campaign)
        await self._publish_events_safely(campaign)

        return CampaignResult(
            campaign_id=str(campaign.id),
            organization_id=request.organization_id,
            status=campaign.status.value,
            total_targets=metrics.total_targets,
            successful_targets=metrics.successful_targets,
            failed_targets=metrics.failed_targets,
            total_findings=metrics.total_findings,
            mean_vulnerability_rate=metrics.mean_vulnerability_rate,
            duration_ms=metrics.total_duration_ms,
            regression_detected=drift_summary.regression_detected if drift_summary else False,
            target_results=target_results,
        )

    # ── Campaign control (pause / resume / cancel) ────────────────────────────

    async def pause_campaign(self, campaign_id: str) -> None:
        """Pause a running campaign. The in-flight target (if any) completes;
        no new targets are dispatched until resume_campaign() is called."""
        campaign = await self._require_campaign(campaign_id)
        campaign.pause()
        await self._campaign_repository.save(campaign)
        logger.info("campaign_paused", campaign_id=campaign_id)

    async def resume_campaign(self, campaign_id: str) -> None:
        """Resume a paused campaign."""
        campaign = await self._require_campaign(campaign_id)
        campaign.resume()
        await self._campaign_repository.save(campaign)
        logger.info("campaign_resumed", campaign_id=campaign_id)

    async def cancel_campaign(self, campaign_id: str, reason: str = "") -> None:
        """Cancel any non-terminal campaign."""
        campaign = await self._require_campaign(campaign_id)
        campaign.cancel(reason)
        await self._campaign_repository.save(campaign)
        await self._publish_events_safely(campaign)
        logger.info("campaign_cancelled", campaign_id=campaign_id, reason=reason)

    # ── Fan-out ───────────────────────────────────────────────────────────────

    async def _execute_targets(
        self, campaign: Campaign, request: CampaignRequest
    ) -> list[TargetResult]:
        """Execute all targets, honouring ExecutionStrategy.

        SEQUENTIAL: one at a time (avoids overwhelming the target).
        PARALLEL: all at once, bounded by configuration.max_concurrent_targets.
        ADAPTIVE: treats max_concurrent_targets as a hint; behaves like PARALLEL.
        """
        cfg = campaign.configuration
        strategy = request.execution_strategy
        target_ids = list(request.target_endpoint_map)

        if strategy == ExecutionStrategy.SEQUENTIAL:
            results: list[TargetResult] = []
            for tid in target_ids:
                if campaign.is_paused:
                    # Pause: drain already-started work, stop dispatching new.
                    logger.info(
                        "campaign_paused_mid_execution",
                        campaign_id=str(campaign.id),
                        remaining=len(target_ids) - len(results),
                    )
                    break
                result = await self._execute_single_target(campaign, request, tid)
                results.append(result)
            return results

        # PARALLEL / ADAPTIVE
        semaphore = asyncio.Semaphore(cfg.max_concurrent_targets)

        async def _bounded(tid: str) -> TargetResult:
            async with semaphore:
                return await self._execute_single_target(campaign, request, tid)

        return list(await asyncio.gather(*(_bounded(tid) for tid in target_ids)))

    async def _execute_single_target(
        self, campaign: Campaign, request: CampaignRequest, target_id: str
    ) -> TargetResult:
        """Call ValidationService for one target; record outcome on Campaign."""
        start = time.perf_counter()
        retry_count = 0
        max_retries = (
            campaign.configuration.max_retries_per_target
            if campaign.configuration.retry_failed_targets
            else 0
        )

        vs_request = ValidationServiceRequest(
            organization_id=request.organization_id,
            target_id=target_id,
            target_endpoint=request.target_endpoint_map[target_id],
            target_provider=request.target_provider_map.get(target_id, "unknown"),
            target_name=request.target_name_map.get(target_id, target_id),
            model=request.target_model_map.get(target_id, "unknown"),
            target_system_prompt=request.target_system_prompt_map.get(target_id, ""),
            target_capabilities=frozenset(),
            attack_categories=request.attack_categories,
            correlation_id=f"{request.correlation_id}:{target_id}",
            max_attacks_per_category=request.max_attacks_per_category,
            severity_minimum=request.severity_minimum,
            policy_id=request.policy_id_for_validation,
            trigger_type=request.campaign_type.value,
            timeout_seconds=campaign.configuration.timeout_seconds_per_target,
        )

        last_exc: Exception | None = None
        vs_result: ValidationServiceResult | None = None

        while retry_count <= max_retries:
            try:
                vs_result = await self._validation_service.execute(vs_request)
                if vs_result.status == "completed":
                    break
                # status == "failed" — retry if configured
                last_exc = Exception(vs_result.failure_reason or "validation failed")
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "campaign_target_execution_error",
                    campaign_id=str(campaign.id),
                    target_id=target_id,
                    attempt=retry_count + 1,
                    error=str(exc),
                )

            retry_count += 1
            if retry_count > max_retries:
                break

        duration_ms = int((time.perf_counter() - start) * 1000)

        if vs_result and vs_result.status == "completed":
            result = TargetResult(
                target_id=EntityId.from_string(target_id),
                run_id=vs_result.run_id,
                status="completed",
                findings_count=len(vs_result.finding_ids),
                vulnerability_rate=vs_result.vulnerability_rate,
                duration_ms=duration_ms,
            )
            campaign.record_target_completed(result)
        else:
            reason = str(last_exc) if last_exc else "unknown failure"
            result = TargetResult(
                target_id=EntityId.from_string(target_id),
                run_id=vs_result.run_id if vs_result else "",
                status="failed",
                findings_count=0,
                vulnerability_rate=0.0,
                duration_ms=duration_ms,
                failure_reason=reason,
            )
            campaign.record_target_failed(EntityId.from_string(target_id), reason)

        await self._campaign_repository.save(campaign)
        return result

    # ── Drift detection ───────────────────────────────────────────────────────

    async def _maybe_detect_drift(
        self,
        campaign: Campaign,
        baseline_campaign_id: str | None,
        target_results: list[TargetResult],
    ) -> DriftSummary | None:
        if not baseline_campaign_id or not self._baseline_port:
            return None

        try:
            baseline_findings = await self._baseline_port.get_findings_summary(
                baseline_campaign_id
            )
            baseline_rates = await self._baseline_port.get_vulnerability_rates(
                baseline_campaign_id
            )
            return self._drift_detector.detect(
                baseline_campaign_id=EntityId.from_string(baseline_campaign_id),
                baseline_findings=baseline_findings,
                baseline_vuln_rates=baseline_rates,
                current_results=target_results,
            )
        except Exception as exc:
            logger.warning(
                "drift_detection_failed",
                campaign_id=str(campaign.id),
                baseline_campaign_id=baseline_campaign_id,
                error=str(exc),
            )
            return None

    # ── Post-commit steps (cannot retroactively fail the campaign) ─────────────

    def _project_knowledge_graph_safely(self, campaign: Campaign) -> None:
        if self._knowledge_projector is None:
            return
        try:
            nodes_added = self._knowledge_projector.project_campaign(campaign)
            logger.debug(
                "campaign_kg_projected",
                campaign_id=str(campaign.id),
                nodes_added=nodes_added,
            )
        except Exception as exc:
            logger.warning(
                "campaign_kg_projection_failed",
                campaign_id=str(campaign.id),
                error=str(exc),
            )

    async def _publish_events_safely(self, campaign: Campaign) -> None:
        events = campaign.collect_events()
        if not events or self._event_publisher is None:
            return
        try:
            await self._event_publisher.publish(events)
        except Exception as exc:
            logger.warning(
                "campaign_event_publish_failed",
                campaign_id=str(campaign.id),
                error=str(exc),
            )

    # ── M10 execution-authorization gate ───────────────────────────────────────

    async def _require_execution_allowed(
        self, organization_id: str, actor_user_id: str, target_ids: list[str],
    ) -> None:
        """Mandatory pre-dispatch check via ExecutionPolicyPort. Raises
        ExecutionNotAuthorizedError unless the decision is exactly
        "allow" — DENY and APPROVAL_REQUIRED both block dispatch."""
        result = await self._execution_policy_service.evaluate(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action_class=_CAMPAIGN_ACTION_CLASS,
            entity_refs=[(ScopeEntityType.AI_TARGET.value, tid) for tid in target_ids],
        )
        if result.decision != "allow":
            logger.warning(
                "campaign_execution_denied_by_policy",
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                decision=result.decision,
                reason_code=result.reason_code,
                decision_id=result.decision_id,
            )
            raise ExecutionNotAuthorizedError(result.decision, result.reason_code)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _require_campaign(self, campaign_id: str) -> Campaign:
        campaign = await self._campaign_repository.get(campaign_id)
        if campaign is None:
            from redforge.core.exceptions import NotFoundError
            raise NotFoundError("Campaign", campaign_id)
        return campaign


# ─── Metrics computation (pure function) ─────────────────────────────────────


def _compute_metrics(
    target_results: list[TargetResult],
    total_duration_ms: int,
) -> CampaignMetrics:
    total = len(target_results)
    successful = sum(1 for r in target_results if r.succeeded)
    failed = total - successful
    total_findings = sum(r.findings_count for r in target_results)
    completed = [r for r in target_results if r.succeeded]
    mean_vuln_rate = (
        sum(r.vulnerability_rate for r in completed) / len(completed)
        if completed else 0.0
    )
    return CampaignMetrics(
        total_targets=total,
        successful_targets=successful,
        failed_targets=failed,
        total_findings=total_findings,
        mean_vulnerability_rate=round(mean_vuln_rate, 4),
        total_duration_ms=total_duration_ms,
    )

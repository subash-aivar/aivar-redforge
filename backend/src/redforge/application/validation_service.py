"""Canonical AI Security Validation Service.

This is the ONE production execution path for all AI security validation.
All other execution paths are adapters or deprecated.

End-to-end flow (see the phase methods below for the concrete mapping):
  ValidationServiceRequest
    → ValidationRun.schedule()   SCHEDULED → RUNNING   (domain entity)
    → _resolve_attacks()                                (AttackResolverPort)
    → _execute_attacks()          per-attack: StepContext → executor → classifier
    → _build_evidence_and_findings()   domain Evidence (append-only) + Finding
    → _correlate_risk()                                 (RiskCorrelationPort)
    → _persist()                  ONE UnitOfWork commit: Evidence + Findings + Run
    → _populate_knowledge_graph_safely()   post-commit, isolated — cannot fail the run
    → _publish_events_safely()             post-commit, isolated — cannot fail the run
    → ValidationServiceResult

Architectural properties:
  - One canonical execution path: no duplicate pipelines.
  - Durable evidence: every step produces a persisted Evidence entity.
  - Evaluation-driven findings: Findings come from the injected classifier's
    ClassificationResult, not from raw StepStatus.
  - Atomic persistence: Evidence + Findings + Run state in one UoW transaction.
  - Post-commit isolation: Knowledge Graph population and event publishing
    happen strictly after a successful commit. Failures there are logged and
    swallowed — they can never retroactively fail an already-persisted run.
  - Failure durability: run.fail() is persisted (best-effort) if anything in
    the execute-through-persist path raises.
  - Protocol-first: every collaborator is injected against a Protocol
    (ResponseClassifier, AttackResolverPort, RiskCorrelationPort,
    KnowledgeGraphPopulatorPort, UnitOfWorkFactory, EventPublisherPort).
    No concrete infrastructure or collaborator class is imported here.
  - Correlation ID propagated through every log line.

On the execution dispatcher: ValidationService intentionally does NOT route
attack execution through ExecutionDispatcher/InProcessDispatcher. That
dispatcher's contract catches StepExecutor exceptions and converts them into
error StepEvidence so a batch keeps going (see application/runtime/dispatcher.py).
ValidationService needs the opposite contract: an unexpected executor
exception must abort the run and durably persist it as FAILED (see
_persist_failure below and ADR-0003's evidence-integrity guarantee — evidence
for a step that never actually completed must not be fabricated). These are
two different error-handling policies for two different callers; reusing the
dispatcher here would silently change failure semantics, so attack dispatch
stays a direct, fail-fast loop over StepExecutor.

Replaces (deprecated):
  - ValidationPipeline (application/pipeline.py)
  - Direct use of ValidationOrchestrator without persistence
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from redforge import __version__ as engine_version
from redforge.application.risk_engine import FindingInput, ValidationResultInput
from redforge.application.runtime.contracts import (
    ClassificationResult,
    ResponseClassifier,
    StepContext,
    StepExecutor,
)
from redforge.application.runtime.orchestrator import AttackStep, ExecutionResult, StepOutcome
from redforge.application.validation_contracts import (
    AttackResolverPort,
    IntelligentClassifier,
    KnowledgeGraphPopulatorPort,
    RiskCorrelationPort,
)
from redforge.application.validation_mappers import (
    SEVERITY_TO_SCORE,
    category_recommendation,
    confidence_to_severity,
    serialize_evidence,
    serialize_finding,
    serialize_validation_run,
)
from redforge.core.logging import get_logger
from redforge.domain.evidence.entity import Evidence
from redforge.domain.evidence.value_objects import (
    AttackReference,
    Confidence,
    EvidenceResult,
    ExecutionMetadata,
    RequestPayload,
    ResponsePayload,
    TestCaseReference,
)
from redforge.domain.findings.entity import Finding
from redforge.domain.findings.value_objects import MitreReference, OwaspReference
from redforge.domain.findings.value_objects import RiskScore as DomainRiskScore
from redforge.domain.validations.entity import ValidationRun
from redforge.domain.validations.value_objects import TriggerType, ValidationSummary
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from redforge.application.contracts import EventPublisherPort, UnitOfWorkFactory
    from redforge.application.red_team.evaluation_intelligence import EvaluationFeedback
    from redforge.application.risk_engine import RiskIncident
    from redforge.application.runtime.evaluation.models import EvaluationIntelligence

logger = get_logger(__name__)

# ─── Request / Result DTOs ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ValidationServiceRequest:
    """Everything the ValidationService needs to execute a validation run.

    Created by API handlers, ScenarioRunner, scheduled jobs, or CI/CD integrations.
    """

    organization_id: str          # EntityId string
    target_id: str                # EntityId string
    target_endpoint: str          # e.g., "https://api.openai.com/v1/chat/completions"
    target_provider: str          # e.g., "openai"
    target_name: str              # Human-readable display name
    model: str                    # e.g., "gpt-4o"
    target_system_prompt: str     # System prompt of the AI under test
    target_capabilities: frozenset[str]  # Capabilities for scenario compat check
    attack_categories: frozenset[str]    # Categories to test against
    correlation_id: str           # Propagated from HTTP request / job ID
    max_attacks_per_category: int = 0   # 0 = no limit
    severity_minimum: str = "low"        # "low" | "medium" | "high" | "critical"
    policy_id: str | None = None
    scenario_id: str | None = None
    trigger_type: str = "manual"
    timeout_seconds: int = 60


@dataclass(frozen=True)
class ValidationServiceResult:
    """Complete result of a ValidationService execution.

    Includes persisted IDs (evidence, findings) so callers can query by ID.
    Includes execution_result for backward compatibility with ScenarioResult.
    """

    run_id: str
    organization_id: str
    target_id: str
    status: str                       # "completed" | "failed"
    total_attacks: int
    passed: int
    failed: int
    errors: int
    inconclusive: int
    duration_ms: int
    evidence_ids: list[str]
    finding_ids: list[str]
    risk_incidents: list[RiskIncident]
    kg_nodes_added: int
    execution_result: ExecutionResult  # For ScenarioResult backward compat
    failure_reason: str | None = None
    # Populated when the pipeline includes ConsensusEngine + EvaluationDrivenIntelligenceAdapter
    evaluation_feedback: EvaluationFeedback | None = None

    @property
    def has_findings(self) -> bool:
        return len(self.finding_ids) > 0

    @property
    def vulnerability_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.failed / self.total_attacks

    @property
    def pass_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return self.passed / self.total_attacks


# ─── Internal phase-to-phase handoff ──────────────────────────────────────────


@dataclass(frozen=True)
class _CommittedRun:
    """Everything a post-commit phase needs. Never leaves ValidationService."""

    run: ValidationRun
    evidence_list: list[Evidence]
    finding_list: list[Finding]
    risk_incidents: list[RiskIncident]
    outcomes: list[StepOutcome]
    passed: int
    failed: int
    errors: int
    inconclusive: int
    duration_ms: int
    evaluation_feedback: EvaluationFeedback | None = None


# ─── Validation Service ───────────────────────────────────────────────────────


class ValidationService:
    """The ONE canonical production execution path for AI security validation.

    Every collaborator is injected against a Protocol — see
    application/validation_contracts.py and application/contracts.py.
    ValidationService imports no concrete infrastructure and no concrete
    collaborator implementation.

    Thread safety: this class is stateless. Each call to execute() creates its
    own local state. Multiple concurrent executions sharing one ValidationService
    instance are safe, provided the injected collaborators are themselves
    concurrency-safe (EvaluationPipeline is; see its module docstring).
    """

    def __init__(
        self,
        executor: StepExecutor,
        classifier: ResponseClassifier,
        attack_resolver: AttackResolverPort,
        risk_engine: RiskCorrelationPort,
        kg_populator: KnowledgeGraphPopulatorPort | None,
        uow_factory: UnitOfWorkFactory,
        event_publisher: EventPublisherPort,
    ) -> None:
        self._executor = executor
        self._classifier = classifier
        self._attack_resolver = attack_resolver
        self._risk_engine = risk_engine
        self._kg_populator = kg_populator
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._evaluation_adapter: object | None = None  # EvaluationDrivenIntelligenceAdapter

    def with_evaluation_adapter(self, adapter: object) -> ValidationService:
        """Attach an EvaluationDrivenIntelligenceAdapter for evaluation quality feedback.

        Returns self for method-chaining at construction time.
        Call this after construction when the adapter is available:
            svc = ValidationService(...).with_evaluation_adapter(adapter)
        """
        self._evaluation_adapter = adapter
        return self

    # ── Public entry point ─────────────────────────────────────────────────

    async def execute(
        self, request: ValidationServiceRequest
    ) -> ValidationServiceResult:
        """Execute a complete AI security validation run.

        Raises whatever the execute-through-persist path raises. On such a
        failure the ValidationRun is marked FAILED and persisted (best-effort)
        before the exception is re-raised. Once persistence has succeeded,
        no later failure (Knowledge Graph, event publishing) can flip the
        run's terminal status.
        """
        correlation_id = request.correlation_id
        start = time.perf_counter()

        logger.info(
            "validation_service_started",
            organization_id=request.organization_id,
            target_id=request.target_id,
            target_provider=request.target_provider,
            attack_categories=sorted(request.attack_categories),
            severity_minimum=request.severity_minimum,
            scenario_id=request.scenario_id,
            correlation_id=correlation_id,
        )

        run = ValidationRun.schedule(
            organization_id=EntityId.from_string(request.organization_id),
            target_id=EntityId.from_string(request.target_id),
            trigger_type=TriggerType(request.trigger_type),
            policy_id=request.policy_id,
        )
        run.start()

        try:
            committed = await self._execute_and_persist(
                request, run, correlation_id, start
            )
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            logger.error(
                "validation_service_failed",
                run_id=str(run.id),
                error=str(exc),
                duration_ms=duration_ms,
                correlation_id=correlation_id,
            )
            await self._persist_failure(run, str(exc))
            raise

        # Post-commit phase: isolated from the transaction above. A failure
        # here is logged, never re-raised, and never touches run status.
        kg_nodes = await self._populate_knowledge_graph_safely(
            request, committed, correlation_id
        )
        await self._publish_events_safely(committed, correlation_id)

        return self._build_result(request, committed, kg_nodes)

    # ── Phase 1-5: execute, evaluate, assemble, correlate, persist ─────────

    async def _execute_and_persist(
        self,
        request: ValidationServiceRequest,
        run: ValidationRun,
        correlation_id: str,
        start: float,
    ) -> _CommittedRun:
        """Everything that must succeed atomically before this run can be
        considered COMPLETED: attack execution, evidence/finding assembly,
        risk correlation, and the single UoW commit.
        """
        attack_steps = await self._resolve_attacks(request, str(run.id), correlation_id)
        outcomes, intelligence_by_step, evaluation_feedback = await self._execute_attacks(
            request, run, attack_steps, correlation_id
        )

        evidence_list, finding_list, finding_to_category = (
            self._build_evidence_and_findings(
                request, run, attack_steps, outcomes, intelligence_by_step,
                correlation_id,
            )
        )

        duration_ms = int((time.perf_counter() - start) * 1000)
        passed = sum(1 for o in outcomes if o.classification.outcome == "pass")
        failed = sum(1 for o in outcomes if o.classification.outcome == "fail")
        errors = sum(1 for o in outcomes if o.classification.outcome == "error")
        inconclusive = sum(
            1 for o in outcomes if o.classification.outcome == "inconclusive"
        )

        risk_incidents = self._correlate_risk(
            request, str(run.id), finding_list, finding_to_category,
            total_checks=len(outcomes), passed=passed, failed=failed,
            duration_ms=duration_ms,
        )

        self._finalize_run_state(run, len(outcomes), passed, failed, errors,
                                  inconclusive, duration_ms)

        await self._persist(run, evidence_list, finding_list, correlation_id)

        return _CommittedRun(
            run=run,
            evidence_list=evidence_list,
            finding_list=finding_list,
            risk_incidents=risk_incidents,
            outcomes=outcomes,
            passed=passed,
            failed=failed,
            errors=errors,
            inconclusive=inconclusive,
            duration_ms=duration_ms,
            evaluation_feedback=evaluation_feedback,
        )

    async def _resolve_attacks(
        self, request: ValidationServiceRequest, run_id: str, correlation_id: str
    ) -> list[AttackStep]:
        """Phase: Attack resolution. Turns category scope into payloads."""
        attack_steps = await self._attack_resolver.resolve(
            categories=request.attack_categories,
            severity_minimum=request.severity_minimum,
            max_per_category=request.max_attacks_per_category,
        )
        logger.info(
            "attacks_resolved",
            run_id=run_id,
            attack_count=len(attack_steps),
            categories=sorted(request.attack_categories),
            correlation_id=correlation_id,
        )
        return attack_steps

    async def _execute_attacks(
        self,
        request: ValidationServiceRequest,
        run: ValidationRun,
        attack_steps: list[AttackStep],
        correlation_id: str,
    ) -> tuple[list[StepOutcome], dict[str, EvaluationIntelligence], EvaluationFeedback | None]:
        """Phase: Attack execution + evaluation.

        Executes each attack against the target and classifies the response.
        Deliberately fail-fast: an exception from the executor propagates
        (see the dispatcher note in the module docstring) so the caller can
        mark the run FAILED rather than fabricate evidence for a step that
        never completed.

        When the injected classifier also satisfies IntelligentClassifier
        (EvaluationPipeline does, via its evaluate() method), the richer
        EvaluationIntelligence for each step is captured here — via a
        single evaluate() call, never both evaluate() and classify() for
        the same step, since some evaluators (e.g. LLMJudgeEvaluator) are
        not guaranteed deterministic and calling both could disagree.
        """
        run_id = str(run.id)
        outcomes: list[StepOutcome] = []
        intelligence_by_step: dict[str, EvaluationIntelligence] = {}
        # Track the best evaluation run result for feedback derivation
        _best_run_result: object | None = None
        _best_category: str = "unknown"
        intelligent_classifier = (
            self._classifier
            if isinstance(self._classifier, IntelligentClassifier)
            else None
        )

        for i, attack_step in enumerate(attack_steps):
            step_id = f"{run_id}-step-{i}"
            category = attack_step.metadata.get("category", "unknown")

            step_context = StepContext(
                step_id=step_id,
                attack_id=attack_step.attack_id,
                attack_name=attack_step.attack_name,
                target_id=request.target_id,
                target_endpoint=request.target_endpoint,
                target_provider=request.target_provider,
                payload_content=attack_step.payload_content,
                timeout_seconds=request.timeout_seconds,
                metadata={
                    **attack_step.metadata,
                    "model": request.model,
                    "correlation_id": correlation_id,
                    "run_id": run_id,
                },
            )

            step_evidence = await self._executor.execute(step_context)

            if step_evidence.is_error:
                classification = ClassificationResult(
                    outcome="error",
                    confidence=1.0,
                    reasoning=step_evidence.error or "Provider execution error",
                )
            else:
                # ValidationService — not the executor — is the reliable
                # source of the attack category (it comes straight from the
                # attack resolver). Executors are not required to round-trip
                # arbitrary StepContext.metadata into StepEvidence.metadata,
                # so evaluation must not depend on them having done so.
                evaluation_evidence = (
                    step_evidence
                    if step_evidence.metadata.get("category") == category
                    else replace(
                        step_evidence,
                        metadata={**step_evidence.metadata, "category": category},
                    )
                )
                if intelligent_classifier is not None:
                    run_result = await intelligent_classifier.evaluate(
                        evaluation_evidence, attack_step.attack_name
                    )
                    classification = run_result.classification
                    if run_result.intelligence is not None:
                        intelligence_by_step[step_id] = run_result.intelligence
                    # Keep the most significant run result for feedback derivation:
                    # prefer VULNERABLE results; else keep the latest
                    if (
                        _best_run_result is None
                        or classification.outcome == "fail"
                    ):
                        _best_run_result = run_result
                        _best_category = category
                else:
                    classification = await self._classifier.classify(
                        evaluation_evidence, attack_step.attack_name
                    )

            logger.info(
                "step_completed",
                run_id=run_id,
                step_id=step_id,
                attack_id=attack_step.attack_id,
                attack_name=attack_step.attack_name,
                category=category,
                outcome=classification.outcome,
                confidence=classification.confidence,
                correlation_id=correlation_id,
            )

            outcomes.append(StepOutcome(
                step_id=step_id,
                attack_id=attack_step.attack_id,
                attack_name=attack_step.attack_name,
                evidence=step_evidence,
                classification=classification,
            ))

        # Derive evaluation feedback if adapter + consensus signals are available
        evaluation_feedback = None
        if (
            self._evaluation_adapter is not None
            and _best_run_result is not None
        ):
            evaluation_feedback = _derive_evaluation_feedback(
                self._evaluation_adapter, _best_run_result, _best_category
            )

        return outcomes, intelligence_by_step, evaluation_feedback

    def _build_evidence_and_findings(
        self,
        request: ValidationServiceRequest,
        run: ValidationRun,
        attack_steps: list[AttackStep],
        outcomes: list[StepOutcome],
        intelligence_by_step: dict[str, EvaluationIntelligence],
        correlation_id: str,
    ) -> tuple[list[Evidence], list[Finding], dict[str, str]]:
        """Phase: Evidence creation + Finding assembly.

        Every step produces a finalized, append-only domain Evidence entity
        (ADR-0003). Steps classified "fail" additionally produce a Finding.

        When EvaluationIntelligence is available for a step (see
        _execute_attacks), the Finding is enriched with matched OWASP/MITRE
        references and an intelligence-derived recommendation using
        Finding's existing mutator methods (add_owasp_reference,
        add_mitre_reference, attach_recommendation) — no domain schema
        change required. The full intelligence record (including matched
        security objectives, threat coverage tags, and the calibration
        risk assessment — fields Finding has no persisted column for yet,
        pending the Security Objective Framework per ADR-0002) is logged
        alongside the finding for audit purposes.
        """
        org_id_entity = EntityId.from_string(request.organization_id)
        target_id_entity = EntityId.from_string(request.target_id)
        result_map = {
            "pass": EvidenceResult.PASS,
            "fail": EvidenceResult.FAIL,
            "error": EvidenceResult.ERROR,
            "inconclusive": EvidenceResult.INCONCLUSIVE,
        }

        evidence_list: list[Evidence] = []
        finding_list: list[Finding] = []
        finding_to_category: dict[str, str] = {}

        for attack_step, outcome in zip(attack_steps, outcomes, strict=True):
            category = attack_step.metadata.get("category", "unknown")
            step_evidence = outcome.evidence
            classification = outcome.classification

            domain_evidence = Evidence.record(
                organization_id=org_id_entity,
                run_id=run.id,
                target_id=target_id_entity,
                test_case_ref=TestCaseReference(
                    test_id=outcome.step_id,
                    test_name=attack_step.attack_name,
                    category=category,
                ),
                attack_ref=AttackReference(
                    attack_id=attack_step.attack_id,
                    attack_name=attack_step.attack_name,
                    attack_type=category,
                ),
                request=RequestPayload(
                    method=step_evidence.request_method,
                    url=step_evidence.request_url,
                    body=step_evidence.request_body,
                ),
                response=ResponsePayload(
                    status_code=step_evidence.response_status,
                    body=step_evidence.response_body,
                    latency_ms=step_evidence.duration_ms,
                ),
                result=result_map.get(classification.outcome, EvidenceResult.INCONCLUSIVE),
                confidence=Confidence(score=classification.confidence),
                execution_metadata=ExecutionMetadata(
                    executed_at=utc_now(),
                    duration_ms=step_evidence.duration_ms,
                    engine_version=engine_version,
                    worker_id=correlation_id,
                ),
            )
            domain_evidence.finalize()
            evidence_list.append(domain_evidence)

            if classification.outcome == "fail":
                severity = confidence_to_severity(classification.confidence)
                attack_display = attack_step.attack_name.replace("_", " ").title()
                intelligence = intelligence_by_step.get(outcome.step_id)
                finding = Finding.create_from_evidence(
                    organization_id=org_id_entity,
                    run_id=run.id,
                    target_id=target_id_entity,
                    evidence_ids=[domain_evidence.id],
                    title=f"Vulnerability Detected: {attack_display}",
                    description=(
                        f"Attack '{attack_step.attack_name}' in category '{category}' "
                        f"detected a security vulnerability with confidence "
                        f"{classification.confidence:.0%}. {classification.reasoning}"
                    ),
                    severity=severity,
                    risk_score=DomainRiskScore(score=SEVERITY_TO_SCORE[severity]),
                    recommendation=(
                        intelligence.recommended_remediation
                        if intelligence and intelligence.recommended_remediation
                        else category_recommendation(category)
                    ),
                )
                if intelligence is not None:
                    self._enrich_finding_with_intelligence(
                        finding, intelligence, correlation_id
                    )
                finding_list.append(finding)
                finding_to_category[str(finding.id)] = category

        return evidence_list, finding_list, finding_to_category

    @staticmethod
    def _enrich_finding_with_intelligence(
        finding: Finding,
        intelligence: EvaluationIntelligence,
        correlation_id: str,
    ) -> None:
        """Attach explainable evaluation output to a Finding.

        Uses Finding's existing mutator methods only — this is an
        additive enrichment of the canonical pipeline, not a domain
        schema change.
        """
        for owasp in intelligence.matched_owasp_controls:
            finding.add_owasp_reference(
                OwaspReference(
                    category_id=owasp.category_id,
                    category_name=owasp.category_name,
                )
            )
        for mitre in intelligence.matched_mitre_techniques:
            finding.add_mitre_reference(
                MitreReference(
                    technique_id=mitre.technique_id,
                    technique_name=mitre.technique_name,
                    tactic=mitre.tactic,
                )
            )

        logger.info(
            "finding_intelligence",
            finding_id=str(finding.id),
            matched_security_objectives=intelligence.matched_security_objectives,
            matched_threat_coverage=intelligence.matched_threat_coverage,
            matched_owasp_controls=[
                m.category_id for m in intelligence.matched_owasp_controls
            ],
            matched_mitre_techniques=[
                m.technique_id for m in intelligence.matched_mitre_techniques
            ],
            supporting_evidence=intelligence.supporting_evidence,
            reasoning_summary=intelligence.reasoning_summary,
            false_positive_risk=intelligence.risk_assessment.false_positive_risk,
            false_negative_risk=intelligence.risk_assessment.false_negative_risk,
            explainability_summary=intelligence.explainability.format_summary(),
            correlation_id=correlation_id,
        )

    def _correlate_risk(
        self,
        request: ValidationServiceRequest,
        run_id: str,
        finding_list: list[Finding],
        finding_to_category: dict[str, str],
        *,
        total_checks: int,
        passed: int,
        failed: int,
        duration_ms: int,
    ) -> list[RiskIncident]:
        """Phase: Risk correlation."""
        finding_inputs: list[FindingInput] = [
            FindingInput(
                finding_id=str(f.id),
                target_id=str(f.target_id),
                organization_id=str(f.organization_id),
                run_id=str(f.run_id),
                severity=str(f.severity),
                risk_score=f.risk_score.score,
                title=f.title,
                evidence_ids=[str(eid) for eid in f.evidence_ids],
                attack_type=finding_to_category.get(str(f.id), ""),
                provider=request.target_provider,
                model=request.model,
            )
            for f in finding_list
        ]
        validation_inputs: list[ValidationResultInput] = [
            ValidationResultInput(
                run_id=run_id,
                target_id=request.target_id,
                organization_id=request.organization_id,
                status="completed",
                total_checks=total_checks,
                failed_checks=failed,
                passed_checks=passed,
                duration_ms=duration_ms,
            )
        ]
        risk_incidents = self._risk_engine.correlate(
            finding_inputs, validations=validation_inputs
        )
        logger.info(
            "risk_correlation_completed",
            run_id=run_id,
            finding_count=len(finding_list),
            incident_count=len(risk_incidents),
        )
        return risk_incidents

    @staticmethod
    def _finalize_run_state(
        run: ValidationRun,
        total: int,
        passed: int,
        failed: int,
        errors: int,
        inconclusive: int,
        duration_ms: int,
    ) -> None:
        """Attach the summary and transition the run to COMPLETED.

        ValidationSummary requires passed + failed + skipped == total_checks.
        errors + inconclusive map to skipped: neither is a pass/fail verdict,
        both mean "not enough signal to classify."
        """
        run.attach_summary(ValidationSummary(
            total_checks=total,
            passed=passed,
            failed=failed,
            skipped=errors + inconclusive,
            duration_ms=duration_ms,
        ))
        run.complete()

    async def _persist(
        self,
        run: ValidationRun,
        evidence_list: list[Evidence],
        finding_list: list[Finding],
        correlation_id: str,
    ) -> None:
        """Phase: Persistence. Evidence + Findings + Run in ONE transaction."""
        async with self._uow_factory() as uow:
            for ev in evidence_list:
                await uow.evidence.save(serialize_evidence(ev))
            for f in finding_list:
                await uow.findings.save(serialize_finding(f))
            await uow.validations.save(serialize_validation_run(run))
            await uow.commit()

        logger.info(
            "validation_persisted",
            run_id=str(run.id),
            evidence_count=len(evidence_list),
            finding_count=len(finding_list),
            correlation_id=correlation_id,
        )

    # ── Phase 6-7: post-commit, isolated ────────────────────────────────────

    async def _populate_knowledge_graph_safely(
        self,
        request: ValidationServiceRequest,
        committed: _CommittedRun,
        correlation_id: str,
    ) -> int:
        """Phase: Knowledge Graph population.

        Strictly post-commit. Any exception here is logged and swallowed —
        it must never cause an already-persisted, successfully COMPLETED
        run to be reported as failed.
        """
        run_id = str(committed.run.id)
        if self._kg_populator is None:
            return 0
        try:
            kg_nodes = self._kg_populator.populate(
                run=committed.run,
                evidence_list=committed.evidence_list,
                finding_list=committed.finding_list,
                risk_incidents=committed.risk_incidents,
                organization_id=request.organization_id,
                target_id=request.target_id,
                target_name=request.target_name,
                target_provider=request.target_provider,
                model=request.model,
                scenario_id=request.scenario_id,
            )
        except Exception as exc:
            logger.error(
                "knowledge_graph_population_failed",
                run_id=run_id,
                error=str(exc),
                correlation_id=correlation_id,
            )
            return 0

        logger.info(
            "knowledge_graph_updated",
            run_id=run_id,
            kg_nodes_added=kg_nodes,
            correlation_id=correlation_id,
        )
        return kg_nodes

    async def _publish_events_safely(
        self, committed: _CommittedRun, correlation_id: str
    ) -> None:
        """Phase: Domain event publishing.

        Strictly post-commit, isolated for the same reason as Knowledge
        Graph population: a downstream consumer or transport failure must
        not retroactively fail an already-persisted, successfully
        COMPLETED run.
        """
        run_id = str(committed.run.id)
        try:
            all_events: list[object] = []
            all_events.extend(committed.run.collect_events())
            for ev in committed.evidence_list:
                all_events.extend(ev.collect_events())
            for f in committed.finding_list:
                all_events.extend(f.collect_events())
            await self._event_publisher.publish(all_events)
        except Exception as exc:
            logger.error(
                "event_publishing_failed",
                run_id=run_id,
                error=str(exc),
                correlation_id=correlation_id,
            )

    # ── Result assembly ────────────────────────────────────────────────────

    @staticmethod
    def _build_result(
        request: ValidationServiceRequest,
        committed: _CommittedRun,
        kg_nodes: int,
    ) -> ValidationServiceResult:
        run_id = str(committed.run.id)
        total = len(committed.outcomes)

        execution_result = ExecutionResult(
            run_id=run_id,
            total_steps=total,
            passed=committed.passed,
            failed=committed.failed,
            errors=committed.errors,
            inconclusive=committed.inconclusive,
            duration_ms=committed.duration_ms,
            outcomes=committed.outcomes,
        )

        logger.info(
            "validation_service_completed",
            run_id=run_id,
            total_attacks=total,
            passed=committed.passed,
            failed=committed.failed,
            finding_count=len(committed.finding_list),
            duration_ms=committed.duration_ms,
            correlation_id=request.correlation_id,
        )

        return ValidationServiceResult(
            run_id=run_id,
            organization_id=request.organization_id,
            target_id=request.target_id,
            status="completed",
            total_attacks=total,
            passed=committed.passed,
            failed=committed.failed,
            errors=committed.errors,
            inconclusive=committed.inconclusive,
            duration_ms=committed.duration_ms,
            evidence_ids=[str(ev.id) for ev in committed.evidence_list],
            finding_ids=[str(f.id) for f in committed.finding_list],
            risk_incidents=committed.risk_incidents,
            kg_nodes_added=kg_nodes,
            execution_result=execution_result,
            evaluation_feedback=committed.evaluation_feedback,
        )

    # ── Failure durability ─────────────────────────────────────────────────

    async def _persist_failure(self, run: ValidationRun, reason: str) -> None:
        """Best-effort persistence of a failed ValidationRun.

        Never raises — failure persistence errors are logged but suppressed
        to preserve the original exception.
        """
        try:
            run.fail(reason)
            async with self._uow_factory() as uow:
                await uow.validations.save(serialize_validation_run(run))
                await uow.commit()
        except Exception as persist_exc:
            logger.error(
                "validation_failure_persist_error",
                run_id=str(run.id),
                error=str(persist_exc),
            )


# ─── Evaluation feedback derivation ──────────────────────────────────────────


def _derive_evaluation_feedback(
    adapter: object,
    run_result: object,
    attack_category: str,
) -> EvaluationFeedback | None:
    """Derive EvaluationFeedback from an EvaluationRunResult if consensus signals exist.

    Called when ValidationService has an EvaluationDrivenIntelligenceAdapter and
    the EvaluationPipeline produced a ConsensusResult. Guards defensively —
    if any required field is missing (pipeline built without consensus_engine),
    returns None rather than raising.
    """
    try:
        from redforge.application.red_team.evaluation_intelligence import (
            AttackOutcomeReasoningService,
            EvaluationDrivenIntelligenceAdapter,
        )
        from redforge.application.runtime.evaluation.policy import (
            PERMISSIVE_POLICY,
            EvaluationPolicyEnforcer,
        )

        if not isinstance(adapter, EvaluationDrivenIntelligenceAdapter):
            return None

        # run_result must be EvaluationRunResult with consensus_result
        consensus = getattr(run_result, "consensus_result", None)
        if consensus is None:
            return None

        aggregated = getattr(run_result, "aggregated", None)
        if aggregated is None:
            return None

        policy_result = getattr(run_result, "policy_result", None)
        if policy_result is None:
            # If no policy was configured, produce a permissive policy result
            enforcer = EvaluationPolicyEnforcer()
            from redforge.application.runtime.evaluation.models import EvaluationContext
            ctx = EvaluationContext(
                step_id="",
                attack_id="",
                attack_name="",
                attack_category=attack_category,
                target_id="",
                request_body="",
                response_body="",
                response_status=200,
                duration_ms=0,
            )
            policy_result = enforcer.check(PERMISSIVE_POLICY, aggregated, consensus, ctx)

        reasoning_svc = AttackOutcomeReasoningService()
        reasoning = reasoning_svc.reason(aggregated, consensus, attack_category)

        return adapter.derive_feedback(
            aggregated,
            consensus,
            policy_result,
            reasoning,
            attack_category,
        )
    except Exception:
        # Feedback derivation is additive — never fail the main execution path
        return None

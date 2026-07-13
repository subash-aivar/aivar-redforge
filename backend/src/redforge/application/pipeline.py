"""AI Security Validation Pipeline — DEPRECATED.

This module is superseded by ValidationService (application/validation_service.py),
which is the ONE canonical production execution pipeline.

ValidationPipeline will be removed in a future release. Do not use it in
new code. Existing references should be migrated to ValidationService.

Reasons for deprecation:
  - Does not run the EvaluationPipeline (classifies by StepStatus only)
  - Does not persist via UnitOfWork (evidence/findings exist in memory only)
  - Does not populate the Knowledge Graph
  - Does not publish domain events
  - Requires pre-resolved AttackDefinitions + PayloadTemplates from callers

Migration:
  Replace ValidationPipeline.execute(PipelineInput) with:
    ValidationService.execute(ValidationServiceRequest)

See application/validation_service.py for the canonical implementation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.value_objects import AttackSeverity
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
from redforge.domain.execution.entity import ExecutionPlan
from redforge.domain.execution.value_objects import (
    ExecutionMode,
    ExecutionStage,
    ExecutionStep,
    FailureStrategy,
    StepStatus,
)
from redforge.domain.findings.entity import Finding
from redforge.domain.findings.value_objects import RiskScore, Severity
from redforge.domain.payloads.entity import PayloadTemplate
from redforge.domain.payloads.value_objects import RenderContext
from redforge.domain.validations.entity import ValidationRun
from redforge.domain.validations.value_objects import TriggerType, ValidationSummary
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from redforge.domain.execution.repository import ProviderAdapter


# ─── Pipeline Result ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PipelineResult:
    """Complete result of a validation pipeline execution."""

    validation_id: str
    execution_plan_id: str
    evidence_ids: list[str]
    finding_ids: list[str]
    attack_count: int
    evidence_count: int
    finding_count: int
    passed: int
    failed: int
    duration_ms: int
    provider_used: str
    risk_summary: str

    @property
    def has_findings(self) -> bool:
        return self.finding_count > 0


# ─── Pipeline Configuration ──────────────────────────────────────────────────


@dataclass(frozen=True)
class PipelineInput:
    """Input for executing the validation pipeline."""

    organization_id: EntityId
    target_id: EntityId
    attacks: list[AttackDefinition]
    templates: list[PayloadTemplate]
    provider_adapter: ProviderAdapter
    trigger_type: TriggerType = TriggerType.MANUAL
    failure_strategy: FailureStrategy = FailureStrategy.CONTINUE
    target_context: dict[str, str] = field(default_factory=dict)


# ─── Pipeline Service ─────────────────────────────────────────────────────────


class ValidationPipeline:
    """Orchestrates the complete AI Security Validation flow.

    Composes existing bounded contexts without containing business logic.
    Every step delegates to the appropriate domain aggregate.
    """

    async def execute(self, input: PipelineInput) -> PipelineResult:
        """Execute the complete validation pipeline."""
        start_time = time.perf_counter()

        # 1. Schedule and start validation run
        run = ValidationRun.schedule(
            organization_id=input.organization_id,
            target_id=input.target_id,
            trigger_type=input.trigger_type,
        )
        run.start()

        # 2. Build execution plan from attacks
        steps = [
            ExecutionStep(
                step_id=f"step-{i}",
                attack_id=str(attack.id),
                target_id=str(input.target_id),
                order=i,
            )
            for i, attack in enumerate(input.attacks)
        ]
        stage = ExecutionStage(
            stage_id="stage-0",
            name="security-validation",
            mode=ExecutionMode.SEQUENTIAL,
            steps=tuple(steps),
        )
        plan = ExecutionPlan.create(
            run_id=run.id,
            policy_id=EntityId.generate(),  # policy ref
            target_id=input.target_id,
            stages=[stage],
            failure_strategy=input.failure_strategy,
        )
        plan.start()

        # 3. Execute each attack
        evidence_list: list[Evidence] = []
        finding_list: list[Finding] = []

        for i, attack in enumerate(input.attacks):
            # Check if plan already terminated (fail-fast)
            if plan.is_terminal:
                break

            # 3a. Resolve template for this attack
            template = self._find_template(attack, input.templates)
            if template is None:
                continue  # Skip attacks without templates

            # 3b. Render payload
            context = RenderContext(
                variables={"payload": f"Attack: {attack.display_name}"},
                target_metadata=input.target_context,
                attack_metadata={"attack_name": attack.name},
            )
            rendered = template.render(context)

            # 3c. Execute via provider adapter
            step_result = await input.provider_adapter.execute_step(
                step_id=f"step-{i}",
                attack_id=str(attack.id),
                target_id=str(input.target_id),
                context={"payload": rendered.content},
            )
            plan.record_step_result(f"step-{i}", step_result)

            # 3d. Record evidence
            evidence = Evidence.record(
                organization_id=input.organization_id,
                run_id=run.id,
                target_id=input.target_id,
                test_case_ref=TestCaseReference(
                    test_id=f"tc-{attack.name}",
                    test_name=attack.display_name,
                    category=str(attack.category),
                ),
                attack_ref=AttackReference(
                    attack_id=str(attack.id),
                    attack_name=attack.name,
                    attack_type=str(attack.category),
                ),
                request=RequestPayload(
                    method="POST",
                    url="target-endpoint",
                    body=rendered.content,
                ),
                response=ResponsePayload(
                    status_code=200,
                    body="provider-response",
                    latency_ms=step_result.duration_ms,
                ),
                result=(
                    EvidenceResult.PASS
                    if step_result.status == StepStatus.COMPLETED
                    else EvidenceResult.FAIL
                ),
                confidence=Confidence(score=0.85),
                execution_metadata=ExecutionMetadata(
                    executed_at=utc_now(),
                    duration_ms=step_result.duration_ms,
                    engine_version="1.0.0",
                ),
            )
            evidence.finalize()
            evidence_list.append(evidence)

            # 3e. Generate finding for failures
            if step_result.status == StepStatus.FAILED:
                finding = Finding.create_from_evidence(
                    organization_id=input.organization_id,
                    run_id=run.id,
                    target_id=input.target_id,
                    evidence_ids=[evidence.id],
                    title=f"Security Issue: {attack.display_name}",
                    description=f"Attack '{attack.name}' detected a vulnerability",
                    severity=self._map_severity(attack.severity),
                    risk_score=RiskScore(score=self._severity_to_score(attack.severity)),
                )
                finding_list.append(finding)

        # 4. Complete plan and run
        if not plan.is_terminal:
            plan.complete()

        passed = plan.completed_steps
        failed = plan.failed_steps
        total = len(input.attacks)
        skipped = total - len(evidence_list)

        run.attach_summary(ValidationSummary(
            total_checks=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            duration_ms=int((time.perf_counter() - start_time) * 1000),
        ))
        run.complete()

        duration_ms = int((time.perf_counter() - start_time) * 1000)

        return PipelineResult(
            validation_id=str(run.id),
            execution_plan_id=str(plan.id),
            evidence_ids=[str(e.id) for e in evidence_list],
            finding_ids=[str(f.id) for f in finding_list],
            attack_count=len(input.attacks),
            evidence_count=len(evidence_list),
            finding_count=len(finding_list),
            passed=passed,
            failed=failed,
            duration_ms=duration_ms,
            provider_used=input.provider_adapter.provider_name,
            risk_summary=self._risk_summary(finding_list),
        )

    # ─── Private Helpers (no business logic — just mapping) ───────────────

    @staticmethod
    def _find_template(
        attack: AttackDefinition, templates: list[PayloadTemplate]
    ) -> PayloadTemplate | None:
        """Find a published template for the given attack."""
        for t in templates:
            if t.attack_id == str(attack.id) and t.is_renderable:
                return t
        # Fallback: first renderable template
        for t in templates:
            if t.is_renderable:
                return t
        return None

    @staticmethod
    def _map_severity(attack_severity: AttackSeverity) -> Severity:
        mapping = {
            AttackSeverity.CRITICAL: Severity.CRITICAL,
            AttackSeverity.HIGH: Severity.HIGH,
            AttackSeverity.MEDIUM: Severity.MEDIUM,
            AttackSeverity.LOW: Severity.LOW,
            AttackSeverity.INFORMATIONAL: Severity.INFORMATIONAL,
        }
        return mapping.get(attack_severity, Severity.MEDIUM)

    @staticmethod
    def _severity_to_score(severity: AttackSeverity) -> float:
        scores = {
            AttackSeverity.CRITICAL: 9.5,
            AttackSeverity.HIGH: 7.5,
            AttackSeverity.MEDIUM: 5.0,
            AttackSeverity.LOW: 2.5,
            AttackSeverity.INFORMATIONAL: 0.5,
        }
        return scores.get(severity, 5.0)

    @staticmethod
    def _risk_summary(findings: list[Finding]) -> str:
        if not findings:
            return "No security issues detected"
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        return f"{len(findings)} findings ({critical} critical, {high} high)"

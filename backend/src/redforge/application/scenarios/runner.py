"""Scenario Runner — bridges ScenarioDefinition to the canonical ValidationService.

Takes a ScenarioDefinition + target info, validates compatibility, builds a
ValidationServiceRequest, delegates execution to ValidationService, then
evaluates success criteria against the results.

The runner does NOT execute attacks directly. It is a thin adapter between
the scenario domain model and the canonical execution pipeline.

Architecture:
  ScenarioRunner.execute(scenario, target, run_id)
    → ValidationServiceRequest
    → ValidationService.execute()      [canonical pipeline, see validation_service.py]
    → ScenarioResult

The DefaultAttackResolver (placeholder strings) is preserved for backward
compatibility but is no longer used in the production path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from redforge.application.runtime.orchestrator import (
    AttackStep,
    ExecutionResult,
)
from redforge.application.scenarios.models import (
    CriteriaResult,
    ScenarioDefinition,
    ScenarioExecutionSummary,
)
from redforge.application.validation_service import (
    ValidationService,
    ValidationServiceRequest,
)


@dataclass(frozen=True, slots=True)
class ScenarioTarget:
    """Target information for scenario execution.

    Simplified view of an AI Target — just what the runner needs.
    """

    target_id: str
    name: str
    endpoint: str
    provider: str
    capabilities: frozenset[str]
    model: str = ""
    system_prompt: str = ""
    organization_id: str = ""


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """Complete result of a scenario execution."""

    scenario_id: str
    scenario_name: str
    target_id: str
    execution_result: ExecutionResult
    summary: ScenarioExecutionSummary
    criteria_result: CriteriaResult
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.criteria_result.passed

    @property
    def pass_rate(self) -> float:
        return self.summary.pass_rate


class ScenarioRunner:
    """Executes a scenario against a target via the canonical ValidationService.

    Responsibilities:
    1. Validate scenario-target compatibility
    2. Build ValidationServiceRequest from scenario + target
    3. Delegate to ValidationService (canonical pipeline)
    4. Evaluate success criteria against results
    5. Return ScenarioResult

    Does NOT execute attacks, evaluate evidence, or generate findings.
    Those are fully handled by ValidationService.
    """

    def __init__(
        self,
        validation_service: ValidationService,
        default_organization_id: str = "",
    ) -> None:
        """Initialize the runner with the canonical validation service.

        Args:
            validation_service: The canonical execution pipeline.
            default_organization_id: Fallback org ID when not set on target.
        """
        self._service = validation_service
        self._default_org_id = default_organization_id

    async def execute(
        self,
        scenario: ScenarioDefinition,
        target: ScenarioTarget,
        run_id: str,
    ) -> ScenarioResult:
        """Execute a scenario against a target.

        Raises ValueError if:
        - Scenario is incompatible with target capabilities.
        - No attacks would be run (empty scope after filtering).
        """
        # 1. Compatibility check
        if not scenario.is_compatible_with(target.capabilities):
            missing = scenario.missing_capabilities(target.capabilities)
            raise ValueError(
                f"Target '{target.name}' missing capabilities: {missing}"
            )

        # 2. Resolve organization ID (prefer target-level, then default)
        organization_id = target.organization_id or self._default_org_id
        if not organization_id:
            raise ValueError(
                f"Cannot execute scenario '{scenario.id}' against target "
                f"'{target.name}': no organization_id was provided on the "
                f"ScenarioTarget and no default_organization_id was configured "
                f"on this ScenarioRunner. Every validation run must be "
                f"organization-scoped (multi-tenant isolation) — refusing to "
                f"invent an identity."
            )

        # 3. Build the ValidationServiceRequest
        request = ValidationServiceRequest(
            organization_id=organization_id,
            target_id=target.target_id,
            target_endpoint=target.endpoint,
            target_provider=target.provider,
            target_name=target.name,
            model=target.model or "gpt-4o",
            target_system_prompt=target.system_prompt,
            target_capabilities=target.capabilities,
            attack_categories=scenario.attack_scope.categories,
            max_attacks_per_category=scenario.attack_scope.max_attacks_per_category,
            severity_minimum=scenario.attack_scope.severity_minimum,
            policy_id=scenario.id,
            scenario_id=scenario.id,
            trigger_type="manual",
            timeout_seconds=60,
            correlation_id=run_id,
        )

        # 4. Delegate to canonical pipeline
        service_result = await self._service.execute(request)

        # 5. Build ScenarioExecutionSummary from service result
        categories_tested = frozenset(
            outcome.evidence.metadata.get("category", "unknown")
            for outcome in service_result.execution_result.outcomes
        )
        high_severity_count = sum(
            1 for inc in service_result.risk_incidents
            if str(inc.priority) in ("critical", "high")
        )
        summary = ScenarioExecutionSummary(
            total_attacks=service_result.total_attacks,
            passed=service_result.passed,
            failed=service_result.failed,
            errors=service_result.errors,
            inconclusive=service_result.inconclusive,
            high_severity_count=high_severity_count,
            categories_tested=categories_tested,
            duration_ms=service_result.duration_ms,
        )

        criteria_result = scenario.success_criteria.evaluate(summary)

        return ScenarioResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            target_id=target.target_id,
            execution_result=service_result.execution_result,
            summary=summary,
            criteria_result=criteria_result,
            metadata={
                "profile_tags": list(scenario.tags),
                "run_id": service_result.run_id,
                "finding_ids": service_result.finding_ids,
                "evidence_ids": service_result.evidence_ids,
                "risk_incident_count": len(service_result.risk_incidents),
                "kg_nodes_added": service_result.kg_nodes_added,
            },
        )


# ─── Legacy Attack Resolver (preserved for backward compatibility) ────────────


class AttackResolver(Protocol):
    """Protocol for resolving attacks from a scenario's scope.

    Kept for backward compatibility. New code should use AttackLibraryResolver
    via ValidationService instead.
    """

    async def resolve(
        self, scenario: ScenarioDefinition, target: ScenarioTarget
    ) -> list[AttackStep]:
        """Resolve attack steps for the given scenario + target."""
        ...


class DefaultAttackResolver:
    """Legacy resolver — generates placeholder attack steps from category names.

    DEPRECATED: Replaced by AttackLibraryResolver used internally by
    ValidationService. This class remains only for legacy tests.
    """

    def __init__(self, payloads: dict[str, list[str]] | None = None) -> None:
        self._payloads = payloads or {}

    async def resolve(
        self, scenario: ScenarioDefinition, target: ScenarioTarget
    ) -> list[AttackStep]:
        """Generate placeholder attack steps from scenario scope."""
        steps: list[AttackStep] = []
        categories = scenario.attack_scope.categories

        for category in sorted(categories):
            category_payloads = self._payloads.get(category, [])
            if not category_payloads:
                category_payloads = [f"[{category}] Security probe for {target.name}"]

            limit = scenario.attack_scope.max_attacks_per_category
            if limit > 0:
                category_payloads = category_payloads[:limit]

            for i, payload in enumerate(category_payloads):
                steps.append(AttackStep(
                    attack_id=f"{category}-{i}",
                    attack_name=f"{category}_attack_{i}",
                    payload_content=payload,
                    metadata={"category": category},
                ))

        return steps

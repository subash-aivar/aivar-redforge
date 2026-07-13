"""Protocol contracts for ValidationService's pluggable collaborators.

Co-located here (rather than in the generic application/contracts.py)
because these protocols are specific to the canonical validation pipeline
and reference validation-pipeline domain types. application/contracts.py
stays reserved for cross-cutting repository/UoW/event ports shared by
every application service.

ValidationService depends only on these protocols — never on the concrete
AttackLibraryResolver, RiskCorrelationEngine, or KnowledgeGraphPopulator
classes. Each protocol has exactly one production implementation today,
but any conforming object (a customer's own attack library adapter, an
alternative risk-scoring engine, a different graph store) can be injected
without modifying ValidationService.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.application.risk_engine import (
        EvidenceChainInput,
        FindingInput,
        RiskIncident,
        ValidationResultInput,
    )
    from redforge.application.runtime.contracts import StepEvidence
    from redforge.application.runtime.evaluation.models import EvaluationRunResult
    from redforge.application.runtime.orchestrator import AttackStep
    from redforge.domain.evidence.entity import Evidence
    from redforge.domain.findings.entity import Finding
    from redforge.domain.validations.entity import ValidationRun


@runtime_checkable
class AttackResolverPort(Protocol):
    """Resolves attack categories into executable AttackStep payloads.

    Implementations: AttackLibraryResolver (built-in library). Enterprise
    customers may implement this against their own attack repository.
    """

    async def resolve(
        self,
        categories: frozenset[str],
        severity_minimum: str = "low",
        max_per_category: int = 0,
    ) -> list[AttackStep]: ...


@runtime_checkable
class RiskCorrelationPort(Protocol):
    """Produces correlated Risk Incidents from findings.

    Implementation: RiskCorrelationEngine.
    """

    def correlate(
        self,
        findings: list[FindingInput],
        chains: list[EvidenceChainInput] | None = None,
        validations: list[ValidationResultInput] | None = None,
    ) -> list[RiskIncident]: ...


@runtime_checkable
class KnowledgeGraphPopulatorPort(Protocol):
    """Populates the Knowledge Graph after a completed validation run.

    Implementation: KnowledgeGraphPopulator. Called strictly post-commit;
    ValidationService treats failures from this port as non-fatal (see
    ValidationService's post-commit isolation).
    """

    def populate(
        self,
        run: ValidationRun,
        evidence_list: list[Evidence],
        finding_list: list[Finding],
        risk_incidents: list[RiskIncident],
        organization_id: str,
        target_id: str,
        target_name: str,
        target_provider: str,
        model: str,
        scenario_id: str | None = None,
    ) -> int: ...


@runtime_checkable
class IntelligentClassifier(Protocol):
    """A ResponseClassifier that can also produce the full, explainable
    EvaluationRunResult — not just pass/fail.

    ValidationService detects this capability structurally (isinstance
    check against this Protocol) rather than requiring it: classifiers
    that only implement ResponseClassifier.classify() (e.g. a bare
    KeywordClassifier, or any customer classifier written before this
    protocol existed) keep working exactly as before, with no
    EvaluationIntelligence attached to findings. EvaluationPipeline
    satisfies both ResponseClassifier and IntelligentClassifier, so
    plugging it in as ValidationService's classifier is what turns the
    intelligence layer on — no ValidationService code change required.

    This is how the Evaluation Intelligence Engine extends the canonical
    pipeline without redesigning it: ValidationService's classifier
    dependency stays typed as ResponseClassifier (the narrower, original
    protocol); IntelligentClassifier is only used for the internal
    capability probe.
    """

    async def evaluate(
        self, evidence: StepEvidence, attack_name: str
    ) -> EvaluationRunResult: ...

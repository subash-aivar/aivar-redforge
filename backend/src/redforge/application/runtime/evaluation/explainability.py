"""ExplainabilityProvider implementations.

Synthesizes the rich EvaluationIntelligence record from an already-decided
AggregatedEvaluation. This module never decides pass/fail — it explains
a verdict Evaluator + ConfidenceAggregator have already reached.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from redforge.application.runtime.evaluation import taxonomy
from redforge.application.runtime.evaluation.models import (
    EvaluationOutcome,
    ExplainabilityTrace,
    MitreTechniqueMatch,
    OwaspControlMatch,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from redforge.application.runtime.evaluation.contracts import ConfidenceCalculator
    from redforge.application.runtime.evaluation.models import (
        AggregatedEvaluation,
        EvaluationContext,
        EvaluationIntelligence,
    )

    TagLookup = Callable[[str], tuple[str, ...]]


@runtime_checkable
class RemediationProvider(Protocol):
    """Supplies remediation copy for a given attack category.

    Kept as a protocol (rather than a bare dict) so enterprise customers
    can back remediation text with a CMS, a compliance knowledge base,
    or per-tenant playbooks instead of a static table.
    """

    def recommend(self, category: str) -> str: ...


class StaticRemediationProvider:
    """Adapts a plain category→text mapping into a RemediationProvider."""

    def __init__(self, recommendations: dict[str, str], default: str = "") -> None:
        self._recommendations = recommendations
        self._default = default

    def recommend(self, category: str) -> str:
        return self._recommendations.get(category.lower(), self._default)


class DefaultExplainabilityProvider:
    """Reference ExplainabilityProvider.

    Sources:
      - matched_owasp_controls / matched_mitre_techniques / matched_
        security_objectives / matched_threat_coverage: from the static
        taxonomy table (taxonomy.py), keyed by attack_category, UNIONED
        with anything an individual evaluator already placed in its
        EvaluatorResult.metadata under the same keys (e.g. LLMJudgeEvaluator
        emits its own matches — those are trusted and merged, not
        overridden, since a judge's category-specific reasoning is more
        precise than the static table).
      - supporting_evidence: every evaluator's `indicators`, deduplicated.
      - reasoning_summary: the aggregator's own reasoning plus a
        one-line-per-evaluator digest.
      - recommended_remediation: delegated to an injected RemediationProvider
        (production wiring backs this with the same category_recommendation()
        table ValidationService uses — see validation_mappers.py — so
        remediation copy has exactly one source of truth).
      - risk_assessment: delegated to the injected ConfidenceCalculator.
    """

    def __init__(
        self,
        confidence_calculator: ConfidenceCalculator,
        remediation_provider: RemediationProvider,
    ) -> None:
        self._confidence_calculator = confidence_calculator
        self._remediation_provider = remediation_provider

    def explain(
        self,
        evaluation: AggregatedEvaluation,
        context: EvaluationContext,
    ) -> EvaluationIntelligence:
        from redforge.application.runtime.evaluation.models import (
            EvaluationIntelligence,
        )

        category = context.attack_category

        owasp_matches = self._merge_owasp(evaluation, category)
        mitre_matches = self._merge_mitre(evaluation, category)
        objectives = self._merge_str_tags(
            evaluation, category, "security_objectives",
            taxonomy.security_objectives_for_category,
        )
        threat_coverage = self._merge_str_tags(
            evaluation, category, "threat_coverage",
            taxonomy.threat_coverage_for_category,
        )

        supporting_evidence = self._collect_supporting_evidence(evaluation)
        risk_assessment = self._confidence_calculator.assess(evaluation, context)
        remediation = (
            self._remediation_provider.recommend(category)
            if evaluation.outcome == EvaluationOutcome.VULNERABLE
            else ""
        )

        trace = ExplainabilityTrace(
            contributing_evaluators=tuple(
                r.evaluator_name for r in evaluation.evaluator_results
            ),
            evaluator_reasonings=tuple(
                (r.evaluator_name, r.reasoning) for r in evaluation.evaluator_results
            ),
            confidence_method=(
                f"{len(evaluation.evaluator_results)}-evaluator aggregation "
                f"({evaluation.agreement_ratio:.0%} agreement)"
            ),
            confidence_rationale=evaluation.reasoning,
            remediation_rationale=self._remediation_rationale(
                evaluation, category, remediation
            ),
        )

        return EvaluationIntelligence(
            matched_security_objectives=objectives,
            matched_threat_coverage=threat_coverage,
            matched_owasp_controls=owasp_matches,
            matched_mitre_techniques=mitre_matches,
            supporting_evidence=supporting_evidence,
            reasoning_summary=self._build_reasoning_summary(evaluation),
            recommended_remediation=remediation,
            risk_assessment=risk_assessment,
            explainability=trace,
        )

    @staticmethod
    def _remediation_rationale(
        evaluation: AggregatedEvaluation, category: str, remediation: str
    ) -> str:
        """Explain precisely why remediation text is or isn't present.

        Two distinct reasons produce an empty `remediation`, and an
        auditor needs to know which one actually happened:
          1. The outcome wasn't VULNERABLE — no remediation is warranted.
          2. The outcome WAS VULNERABLE, but the RemediationProvider has
             no copy for this specific category — a knowledge-base gap,
             not a security judgment.
        """
        if remediation:
            return (
                f"Category '{category}' matches the reference remediation "
                f"playbook for this attack type."
            )
        if evaluation.outcome != EvaluationOutcome.VULNERABLE:
            return "No remediation recommended — outcome was not VULNERABLE."
        return (
            f"Outcome was VULNERABLE, but no remediation playbook entry "
            f"exists for category '{category}'."
        )

    @staticmethod
    def _build_reasoning_summary(evaluation: AggregatedEvaluation) -> str:
        parts = [evaluation.reasoning] if evaluation.reasoning else []
        for r in evaluation.evaluator_results:
            if r.reasoning:
                parts.append(f"{r.evaluator_name}: {r.reasoning}")
        return " | ".join(parts) if parts else "No reasoning available."

    @staticmethod
    def _collect_supporting_evidence(
        evaluation: AggregatedEvaluation,
    ) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for r in evaluation.evaluator_results:
            for indicator in r.indicators:
                seen.setdefault(indicator, None)
        return tuple(seen.keys())

    @staticmethod
    def _merge_owasp(
        evaluation: AggregatedEvaluation, category: str
    ) -> tuple[OwaspControlMatch, ...]:
        from_table = taxonomy.owasp_controls_for_category(category)
        from_evaluators: dict[str, OwaspControlMatch] = {
            m.category_id: m for m in from_table
        }
        for r in evaluation.evaluator_results:
            for match in r.metadata.get("owasp_controls", ()):
                if isinstance(match, OwaspControlMatch):
                    from_evaluators[match.category_id] = match
        return tuple(from_evaluators.values())

    @staticmethod
    def _merge_mitre(
        evaluation: AggregatedEvaluation, category: str
    ) -> tuple[MitreTechniqueMatch, ...]:
        from_evaluators: dict[str, MitreTechniqueMatch] = {}
        table_match = taxonomy.mitre_technique_for_category(category)
        if table_match is not None:
            from_evaluators[table_match.technique_id] = table_match
        for r in evaluation.evaluator_results:
            for match in r.metadata.get("mitre_techniques", ()):
                if isinstance(match, MitreTechniqueMatch):
                    from_evaluators[match.technique_id] = match
        return tuple(from_evaluators.values())

    @staticmethod
    def _merge_str_tags(
        evaluation: AggregatedEvaluation,
        category: str,
        metadata_key: str,
        table_lookup: TagLookup,
    ) -> tuple[str, ...]:
        tags: dict[str, None] = dict.fromkeys(table_lookup(category))
        for r in evaluation.evaluator_results:
            for tag in r.metadata.get(metadata_key, ()):
                if isinstance(tag, str):
                    tags.setdefault(tag, None)
        return tuple(tags.keys())

"""Finding candidate generation from evaluation results.

Converts VULNERABLE evaluations into structured FindingCandidate
objects. These are passed to the existing Findings domain for
persistence — this module does NOT create domain entities directly.
"""

from __future__ import annotations

from redforge.application.runtime.evaluation.models import (
    AggregatedEvaluation,
    EvaluationContext,
    EvaluationOutcome,
    FindingCandidate,
)

# Severity mapping based on confidence + attack category
_SEVERITY_THRESHOLDS = {
    0.9: "critical",
    0.75: "high",
    0.5: "medium",
    0.25: "low",
    0.0: "informational",
}


class DefaultFindingGenerator:
    """Generates finding candidates from vulnerable evaluations.

    Produces a FindingCandidate with appropriate severity
    based on confidence and attack metadata. Returns None
    for non-vulnerable evaluations.
    """

    def generate(
        self, evaluation: AggregatedEvaluation, context: EvaluationContext
    ) -> FindingCandidate | None:
        """Generate a finding candidate if evaluation indicates vulnerability."""
        if evaluation.outcome != EvaluationOutcome.VULNERABLE:
            return None

        severity = self._determine_severity(evaluation.confidence)
        indicators: list[str] = []
        for r in evaluation.evaluator_results:
            indicators.extend(r.indicators)

        description = (
            f"Attack '{context.attack_name}' ({context.attack_category}) "
            f"succeeded against target {context.target_id}. "
            f"Confidence: {evaluation.confidence:.0%}. "
            f"Evaluators: {evaluation.evaluator_count} "
            f"({evaluation.agreement_ratio:.0%} agreement)."
        )

        evidence_summary = (
            f"Request: {context.request_body[:200]}... | "
            f"Response: {context.response_body[:200]}..."
            if len(context.response_body) > 200
            else f"Request: {context.request_body[:200]} | "
            f"Response: {context.response_body}"
        )

        return FindingCandidate(
            attack_id=context.attack_id,
            attack_name=context.attack_name,
            attack_category=context.attack_category,
            target_id=context.target_id,
            step_id=context.step_id,
            title=f"{context.attack_category.replace('_', ' ').title()} Vulnerability Detected",
            description=description,
            severity=severity,
            confidence=evaluation.confidence,
            evidence_summary=evidence_summary,
            recommendation=self._recommendation_for(context.attack_category),
            metadata={
                "indicators": indicators,
                "evaluator_count": evaluation.evaluator_count,
                "agreement_ratio": evaluation.agreement_ratio,
            },
        )

    @staticmethod
    def _determine_severity(confidence: float) -> str:
        """Map confidence to severity level."""
        for threshold, severity in sorted(
            _SEVERITY_THRESHOLDS.items(), reverse=True
        ):
            if confidence >= threshold:
                return severity
        return "informational"

    @staticmethod
    def _recommendation_for(category: str) -> str:
        """Provide category-specific remediation guidance."""
        recommendations = {
            "prompt_injection": "Implement input validation and instruction hierarchy",
            "jailbreak": "Strengthen system prompt guardrails and content filters",
            "data_exfiltration": "Apply output filtering and PII detection",
            "tool_abuse": "Restrict tool access and validate tool call parameters",
            "system_prompt_leakage": "Protect system prompt with anti-extraction measures",
        }
        return recommendations.get(
            category, "Review and strengthen AI security controls"
        )

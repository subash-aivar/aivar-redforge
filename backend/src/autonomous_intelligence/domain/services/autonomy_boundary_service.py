from __future__ import annotations

from autonomous_intelligence.domain.exceptions.domain_exceptions import AutonBoundaryViolation


class AutonomyBoundaryService:
    """Guards ADR-M36-001 — no direct cross-context mutation."""

    FORBIDDEN_MUTATIONS = frozenset(
        {
            "DetectionRule",
            "RuleVersion",
            "ScenarioTemplate",
            "PlaybookVersion",
            "Vulnerability",
        }
    )

    def assert_no_direct_mutation(self, target_aggregate_name: str) -> None:
        if target_aggregate_name in self.FORBIDDEN_MUTATIONS:
            raise AutonBoundaryViolation(
                f"direct mutation of {target_aggregate_name} is forbidden; "
                "publish SuggestionProposedForApplication instead"
            )

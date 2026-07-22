from __future__ import annotations

import pytest

from autonomous_intelligence.domain.exceptions.domain_exceptions import AutonBoundaryViolation
from autonomous_intelligence.domain.services.autonomy_boundary_service import (
    AutonomyBoundaryService,
)


def test_suggestion_proposal_never_mutates_target_context_directly() -> None:
    svc = AutonomyBoundaryService()
    for name in (
        "DetectionRule",
        "RuleVersion",
        "ScenarioTemplate",
        "PlaybookVersion",
        "Vulnerability",
    ):
        with pytest.raises(AutonBoundaryViolation):
            svc.assert_no_direct_mutation(name)

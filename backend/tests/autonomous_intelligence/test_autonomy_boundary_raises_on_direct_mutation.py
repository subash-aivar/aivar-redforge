from __future__ import annotations

import pytest

from autonomous_intelligence.domain.exceptions.domain_exceptions import AutonBoundaryViolation
from autonomous_intelligence.domain.services.autonomy_boundary_service import (
    AutonomyBoundaryService,
)


def test_autonomy_boundary_raises_on_direct_mutation() -> None:
    svc = AutonomyBoundaryService()
    with pytest.raises(AutonBoundaryViolation):
        svc.assert_no_direct_mutation("DetectionRule")
    with pytest.raises(AutonBoundaryViolation):
        svc.assert_no_direct_mutation("PlaybookVersion")
    svc.assert_no_direct_mutation("IntelligenceSuggestion")

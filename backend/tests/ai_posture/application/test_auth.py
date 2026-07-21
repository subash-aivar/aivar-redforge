"""Authorization tests for ai_posture role hierarchy."""

from __future__ import annotations

import pytest

from ai_posture.application._auth import require_at_least
from ai_posture.application.exceptions import ApplicationForbiddenError
from ai_posture.domain.value_objects.enums import AIPostureRole


def test_engineer_satisfies_analyst() -> None:
    require_at_least(("ai_posture:engineer",), AIPostureRole.ANALYST)


def test_reader_forbidden_for_engineer_action() -> None:
    with pytest.raises(ApplicationForbiddenError):
        require_at_least(("ai_posture:reader",), AIPostureRole.ENGINEER)


def test_auditor_is_read_only() -> None:
    with pytest.raises(ApplicationForbiddenError):
        require_at_least(("ai_posture:auditor",), AIPostureRole.ANALYST)


def test_canonical_role_names() -> None:
    assert AIPostureRole.ENGINEER.value == "ai_posture:engineer"
    assert "mlsecops:engineer" not in {r.value for r in AIPostureRole}

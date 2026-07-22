from __future__ import annotations

import pytest

from playbook.domain.exceptions.domain_exceptions import (
    PlaybookAuthorizationDenied,
    SeparationOfDutiesViolation,
)
from playbook.domain.services.playbook_authorization_service import PlaybookAuthorizationService
from playbook.domain.value_objects.enums import ActionImpactLevel


@pytest.fixture
def svc() -> PlaybookAuthorizationService:
    return PlaybookAuthorizationService()


@pytest.mark.parametrize(
    ("level", "role", "ok"),
    [
        (ActionImpactLevel.LOW, "soc:analyst", True),
        (ActionImpactLevel.LOW, "playbook:engineer", False),
        (ActionImpactLevel.MEDIUM, "soc:commander", True),
        (ActionImpactLevel.MEDIUM, "soc:analyst", False),
        (ActionImpactLevel.HIGH, "soc:commander", True),
        (ActionImpactLevel.HIGH, "soc:analyst", False),
        (ActionImpactLevel.CRITICAL, "incident:ciso", True),
        (ActionImpactLevel.CRITICAL, "soc:commander", True),
    ],
)
def test_approval_matrix(
    svc: PlaybookAuthorizationService, level: ActionImpactLevel, role: str, ok: bool
) -> None:
    if ok:
        svc.assert_approval_authorized(level, (role,))
    else:
        with pytest.raises(PlaybookAuthorizationDenied):
            svc.assert_approval_authorized(level, (role,))


def test_quorum_high_critical(svc: PlaybookAuthorizationService) -> None:
    assert svc.approval_requirements(ActionImpactLevel.HIGH)[1] == 2
    assert svc.approval_requirements(ActionImpactLevel.CRITICAL)[1] == 2
    assert svc.approval_requirements(ActionImpactLevel.LOW)[1] == 1


def test_runtime_auto_execute(svc: PlaybookAuthorizationService) -> None:
    assert svc.runtime_authorization_required(ActionImpactLevel.LOW) is None
    assert svc.runtime_authorization_required(ActionImpactLevel.MEDIUM) is None
    assert svc.runtime_authorization_required(ActionImpactLevel.HIGH) == "soc:commander"
    assert svc.runtime_authorization_required(ActionImpactLevel.CRITICAL) == "incident:ciso"


def test_runtime_sod(svc: PlaybookAuthorizationService) -> None:
    with pytest.raises(SeparationOfDutiesViolation):
        svc.assert_runtime_authorized(ActionImpactLevel.HIGH, ("soc:commander",), "op1", "op1")
    svc.assert_runtime_authorized(ActionImpactLevel.HIGH, ("soc:commander",), "op2", "op1")


def test_runtime_role_denied(svc: PlaybookAuthorizationService) -> None:
    with pytest.raises(PlaybookAuthorizationDenied):
        svc.assert_runtime_authorized(ActionImpactLevel.CRITICAL, ("soc:commander",), "op2", "op1")

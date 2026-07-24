from __future__ import annotations

import pytest

from siem_investigation.application.ports.investigation_evaluation_result import (
    InvestigationEvaluationResult,
)
from siem_investigation.domain.value_objects.enums import TimelineScopeType


def test_construction() -> None:
    result = InvestigationEvaluationResult(
        should_investigate=True,
        scope_type=TimelineScopeType.ENTITY,
        scope_ref="entity-1",
        summary="x",
        reason="y",
    )
    assert result.should_investigate is True


def test_blank_scope_ref_rejected() -> None:
    with pytest.raises(ValueError, match="scope_ref"):
        InvestigationEvaluationResult(
            should_investigate=True,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="  ",
            summary="x",
            reason="y",
        )


def test_blank_summary_rejected() -> None:
    with pytest.raises(ValueError, match="summary"):
        InvestigationEvaluationResult(
            should_investigate=True,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            summary="",
            reason="y",
        )


def test_blank_reason_rejected() -> None:
    with pytest.raises(ValueError, match="reason"):
        InvestigationEvaluationResult(
            should_investigate=True,
            scope_type=TimelineScopeType.ENTITY,
            scope_ref="entity-1",
            summary="x",
            reason="   ",
        )

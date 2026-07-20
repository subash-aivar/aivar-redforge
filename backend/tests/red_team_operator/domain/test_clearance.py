"""Clearance ↔ impact ceiling and approval-scope mapping (ADR-M29-007)."""

from __future__ import annotations

from red_team_operator.domain.value_objects.clearance import (
    can_authorize_ceiling,
    clearance_meets_scope,
    max_impact_ceiling,
    min_clearance_for_scope,
)
from red_team_operator.domain.value_objects.enums import (
    ApprovalScope,
    ImpactCeiling,
    OperatorClearanceLevel,
)


class TestMaxImpactCeiling:
    def test_clearance_to_ceiling_mapping(self) -> None:
        assert max_impact_ceiling(OperatorClearanceLevel.L1) == ImpactCeiling.OBSERVE
        assert max_impact_ceiling(OperatorClearanceLevel.L2) == ImpactCeiling.PROBE
        assert max_impact_ceiling(OperatorClearanceLevel.L3) == ImpactCeiling.EXPLOIT
        assert max_impact_ceiling(OperatorClearanceLevel.L4_CISO) == ImpactCeiling.DESTRUCT

    def test_l1_cannot_authorize_exploit(self) -> None:
        assert can_authorize_ceiling(OperatorClearanceLevel.L1, ImpactCeiling.EXPLOIT) is False
        assert can_authorize_ceiling(OperatorClearanceLevel.L3, ImpactCeiling.EXPLOIT) is True
        assert can_authorize_ceiling(OperatorClearanceLevel.L3, ImpactCeiling.DESTRUCT) is False
        assert can_authorize_ceiling(OperatorClearanceLevel.L4_CISO, ImpactCeiling.DESTRUCT) is True


class TestApprovalScopeMinimums:
    def test_approval_scopes_require_l3(self) -> None:
        for scope in ApprovalScope:
            assert min_clearance_for_scope(scope) == OperatorClearanceLevel.L3
            assert clearance_meets_scope(OperatorClearanceLevel.L2, scope) is False
            assert clearance_meets_scope(OperatorClearanceLevel.L3, scope) is True
            assert clearance_meets_scope(OperatorClearanceLevel.L4_CISO, scope) is True

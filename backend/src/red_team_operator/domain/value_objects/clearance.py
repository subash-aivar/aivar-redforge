"""Clearance ↔ impact-ceiling mapping and approval-scope minimums (ADR-M29-007)."""

from __future__ import annotations

from red_team_operator.domain.value_objects.enums import (
    ApprovalScope,
    ImpactCeiling,
    OperatorClearanceLevel,
)

_CLEARANCE_RANK: dict[OperatorClearanceLevel, int] = {
    OperatorClearanceLevel.L1: 1,
    OperatorClearanceLevel.L2: 2,
    OperatorClearanceLevel.L3: 3,
    OperatorClearanceLevel.L4_CISO: 4,
}

_IMPACT_RANK: dict[ImpactCeiling, int] = {
    ImpactCeiling.OBSERVE: 1,
    ImpactCeiling.PROBE: 2,
    ImpactCeiling.EXPLOIT: 3,
    ImpactCeiling.DESTRUCT: 4,
}

_IMPACT_CEILING_BY_CLEARANCE: dict[OperatorClearanceLevel, ImpactCeiling] = {
    OperatorClearanceLevel.L1: ImpactCeiling.OBSERVE,
    OperatorClearanceLevel.L2: ImpactCeiling.PROBE,
    OperatorClearanceLevel.L3: ImpactCeiling.EXPLOIT,
    OperatorClearanceLevel.L4_CISO: ImpactCeiling.DESTRUCT,
}

# Approval authority requires L3+ for all listed scopes.
# Authorizing Destruct impact still requires L4_CISO via max_impact_ceiling.
_MIN_CLEARANCE_FOR_SCOPE: dict[ApprovalScope, OperatorClearanceLevel] = {
    ApprovalScope.ENGAGEMENT_APPROVAL: OperatorClearanceLevel.L3,
    ApprovalScope.OPERATION_APPROVAL: OperatorClearanceLevel.L3,
    ApprovalScope.PAYLOAD_APPROVAL: OperatorClearanceLevel.L3,
}


def clearance_rank(level: OperatorClearanceLevel) -> int:
    return _CLEARANCE_RANK[level]


def impact_rank(ceiling: ImpactCeiling) -> int:
    return _IMPACT_RANK[ceiling]


def max_impact_ceiling(level: OperatorClearanceLevel) -> ImpactCeiling:
    """Map clearance level to the maximum impact ceiling the operator may authorize."""
    return _IMPACT_CEILING_BY_CLEARANCE[level]


def min_clearance_for_scope(scope: ApprovalScope) -> OperatorClearanceLevel:
    return _MIN_CLEARANCE_FOR_SCOPE[scope]


def clearance_meets_scope(
    level: OperatorClearanceLevel,
    scope: ApprovalScope,
) -> bool:
    return clearance_rank(level) >= clearance_rank(min_clearance_for_scope(scope))


def can_authorize_ceiling(
    level: OperatorClearanceLevel,
    ceiling: ImpactCeiling,
) -> bool:
    """True when clearance max impact is at least the requested ceiling."""
    return impact_rank(max_impact_ceiling(level)) >= impact_rank(ceiling)

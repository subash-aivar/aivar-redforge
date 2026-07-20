"""Enumerations for the operator domain."""

from __future__ import annotations

from enum import StrEnum


class OperatorClearanceLevel(StrEnum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4_CISO = "L4_CISO"


class OperatorState(StrEnum):
    ACTIVE = "Active"
    SUSPENDED = "Suspended"
    REVOKED = "Revoked"


class ApprovalScope(StrEnum):
    ENGAGEMENT_APPROVAL = "EngagementApproval"
    OPERATION_APPROVAL = "OperationApproval"
    PAYLOAD_APPROVAL = "PayloadApproval"


class ImpactCeiling(StrEnum):
    """Technique impact ceiling an operator may authorize (ADR-M29-007)."""

    OBSERVE = "Observe"
    PROBE = "Probe"
    EXPLOIT = "Exploit"
    DESTRUCT = "Destruct"

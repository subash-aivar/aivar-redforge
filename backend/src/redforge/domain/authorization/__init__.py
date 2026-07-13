"""Security Authorization bounded context (M10).

The AUTHORIZED PT SCOPE & EXECUTION POLICY control plane. Decides
ALLOW / DENY / APPROVAL_REQUIRED for future active security-testing
actions. Does not execute anything itself.
"""

from redforge.domain.authorization.entity import (
    AuthorizationApproval,
    SecurityAuthorization,
)
from redforge.domain.authorization.repository import (
    AuthorizationApprovalRepository,
    ExecutionPolicyDecisionRepository,
    SecurityAuthorizationRepository,
)
from redforge.domain.authorization.value_objects import (
    ActionClass,
    ApprovalDecision,
    AuthorizationScopeEntry,
    AuthorizationStatus,
    ExecutionPolicyDecision,
    PolicyDecision,
    ReasonCode,
    ScopeEntityType,
    ValidityWindow,
)

__all__ = [
    "ActionClass",
    "ApprovalDecision",
    "AuthorizationApproval",
    "AuthorizationApprovalRepository",
    "AuthorizationScopeEntry",
    "AuthorizationStatus",
    "ExecutionPolicyDecision",
    "ExecutionPolicyDecisionRepository",
    "PolicyDecision",
    "ReasonCode",
    "ScopeEntityType",
    "SecurityAuthorization",
    "SecurityAuthorizationRepository",
    "ValidityWindow",
]

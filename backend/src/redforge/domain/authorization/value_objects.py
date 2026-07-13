"""Value objects for the Security Authorization bounded context (M10).

This bounded context is the AUTHORIZED PT SCOPE & EXECUTION POLICY
control plane. It decides ALLOW / DENY / APPROVAL_REQUIRED for a future
active security-testing action. It does not execute anything itself —
see domain/execution and application/campaigns for the (currently
inert/read-only) execution surfaces this gate protects.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@unique
class AuthorizationStatus(StrEnum):
    """Lifecycle status of a SecurityAuthorization.

    Legal transitions (enforced by SecurityAuthorization, no others exist):
        DRAFT -> PENDING_APPROVAL
        PENDING_APPROVAL -> ACTIVE
        PENDING_APPROVAL -> REJECTED
        ACTIVE -> REVOKED
        ACTIVE -> EXPIRED

    REJECTED, REVOKED, and EXPIRED are terminal. A rejected or expired
    authorization is never resurrected in place — a new DRAFT
    authorization must be created (see entity.py module docstring for
    the reasoning: this keeps approval history immutable and honest).
    """

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    REJECTED = "rejected"
    REVOKED = "revoked"
    EXPIRED = "expired"


@unique
class ActionClass(StrEnum):
    """Closed, server-controlled taxonomy of requestable action classes.

    This is POLICY CLASSIFICATION only — it does not implement any of
    these actions. Classification is by this enum value alone, never by
    display name or free text (ActionClass(raw_string) raises ValueError
    for anything not in this enum, which ExecutionPolicyService treats
    as ACTION_CLASS_DENIED — see execution_policy_service.py).
    """

    PASSIVE_DISCOVERY = "passive_discovery"
    READ_ONLY_ASSESSMENT = "read_only_assessment"
    SAFE_VALIDATION = "safe_validation"
    ACTIVE_VALIDATION = "active_validation"
    CREDENTIAL_VALIDATION = "credential_validation"
    EXPLOIT_EXECUTION = "exploit_execution"
    POST_EXPLOITATION = "post_exploitation"
    DESTRUCTIVE_ACTION = "destructive_action"


# Action classes that are ALWAYS denied in M10, unconditionally, even if
# an ACTIVE authorization's scope happens to list them. No execution
# capability for these exists anywhere in the platform yet (M10 builds
# only the control plane) — an authorization is never allowed to grant
# eligibility for a capability that cannot be safely gated because it
# does not exist. Revisiting this set is an M11+ decision, not a
# configuration knob.
CATEGORICALLY_DENIED_ACTION_CLASSES: frozenset[ActionClass] = frozenset({
    ActionClass.EXPLOIT_EXECUTION,
    ActionClass.POST_EXPLOITATION,
    ActionClass.DESTRUCTIVE_ACTION,
})

# Action classes an authorization MAY legally grant. Kept as an explicit
# allowlist (rather than "everything not categorically denied") so a
# future new enum member defaults to unauthorizable until a deliberate
# decision is made to add it here.
AUTHORIZABLE_ACTION_CLASSES: frozenset[ActionClass] = frozenset({
    ActionClass.PASSIVE_DISCOVERY,
    ActionClass.READ_ONLY_ASSESSMENT,
    ActionClass.SAFE_VALIDATION,
    ActionClass.ACTIVE_VALIDATION,
    ActionClass.CREDENTIAL_VALIDATION,
})

# CREDENTIAL_VALIDATION requires a strictly stronger approval permission
# than the other authorizable classes (Permission.AUTHORIZATIONS_APPROVE_CREDENTIAL
# vs Permission.AUTHORIZATIONS_APPROVE) — see api/security.py and
# application/authorization/service.py's approve() use case.
STRONG_APPROVAL_ACTION_CLASSES: frozenset[ActionClass] = frozenset({
    ActionClass.CREDENTIAL_VALIDATION,
})


@unique
class ScopeEntityType(StrEnum):
    """Canonical entity types an AuthorizationScope entry may reference.

    Deliberately limited to entity types this codebase has canonical,
    tenant-owned identity for today (AITarget from M1, AIAsset from
    M22's inventory bounded context). No free-text hostname/display-name
    scoping is supported — see AuthorizationScope's docstring.
    """

    AI_TARGET = "ai_target"
    AI_ASSET = "ai_asset"


@unique
class ApprovalDecision(StrEnum):
    """Terminal decision recorded on an AuthorizationApproval."""

    APPROVED = "approved"
    REJECTED = "rejected"


@unique
class PolicyDecision(StrEnum):
    """The three possible outcomes of ExecutionPolicyService.evaluate()."""

    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


@unique
class ReasonCode(StrEnum):
    """Server-controlled reason codes for a PolicyDecision.

    Never derived from client input — evaluate() computes exactly one
    of these per call. Exposing only a closed enum (rather than a free
    string) prevents leaking internal implementation detail through the
    API while still being independently auditable.
    """

    ALLOWED_BY_ACTIVE_AUTHORIZATION = "ALLOWED_BY_ACTIVE_AUTHORIZATION"
    AUTHORIZATION_NOT_FOUND = "AUTHORIZATION_NOT_FOUND"
    AUTHORIZATION_NOT_ACTIVE = "AUTHORIZATION_NOT_ACTIVE"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    ACTION_NOT_IN_SCOPE = "ACTION_NOT_IN_SCOPE"
    ENTITY_NOT_IN_SCOPE = "ENTITY_NOT_IN_SCOPE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SELF_APPROVAL_FORBIDDEN = "SELF_APPROVAL_FORBIDDEN"
    ACTION_CLASS_DENIED = "ACTION_CLASS_DENIED"
    TENANT_MISMATCH = "TENANT_MISMATCH"


@dataclass(frozen=True, slots=True)
class ValidityWindow:
    """A half-open [valid_from, valid_until) time window.

    Expiry is always computed from `now` at evaluation time, never
    trusted from a stored status flag alone — this is what makes
    time-of-use enforcement correct even if a background sweep job that
    flips ACTIVE -> EXPIRED has not yet run (mirrors
    domain.identity.entities.Invitation.is_expired()).
    """

    valid_from: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")

    def is_expired(self, now: datetime) -> bool:
        return now >= self.valid_until

    def is_not_yet_valid(self, now: datetime) -> bool:
        return now < self.valid_from

    def contains(self, now: datetime) -> bool:
        return not self.is_not_yet_valid(now) and not self.is_expired(now)


@dataclass(frozen=True, slots=True)
class AuthorizationScopeEntry:
    """One canonical entity in an AuthorizationScope.

    Scope is exact and machine-enforceable: (entity_type, entity_id)
    referencing a canonical, tenant-owned identity. No display-name or
    substring matching — the application layer is responsible for
    verifying entity_id actually resolves to a real, same-tenant entity
    before it is ever attached to an authorization (see
    application/authorization/service.py's create()/add_scope()).
    """

    entity_type: ScopeEntityType
    entity_id: str

    def __post_init__(self) -> None:
        if not self.entity_id or not self.entity_id.strip():
            raise ValueError("entity_id must not be empty")


@dataclass(frozen=True, slots=True)
class ExecutionPolicyDecision:
    """The outcome of one ExecutionPolicyService.evaluate() call.

    This is the canonical, auditable decision record. `decision_id` is
    only populated once persisted (see application layer) — the domain
    value object itself has no persistence concept.
    """

    decision: PolicyDecision
    reason_code: ReasonCode
    action_class: ActionClass | None
    entity_refs: tuple[AuthorizationScopeEntry, ...]
    authorization_id: str | None
    evaluated_at: datetime

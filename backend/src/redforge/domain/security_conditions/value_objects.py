"""Value objects for the Security Condition bounded context — M8.

A SecurityCondition is a deterministic security-relevant condition
identified by a rule/check against canonical asset state — distinct
from both a raw exposure observation (an unstructured fact, e.g. "SSH
observed") and a validated Finding (explicit validation-mechanism
evidence, owned by `domain/findings/`). This bounded context does NOT
weaken or replace Finding semantics — Finding remains the canonical
validated-security-assessment aggregate; SecurityCondition is a
distinct, earlier-stage truth in the OBSERVED/INFERRED/VALIDATED
evidence chain.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class EvidenceState(StrEnum):
    """OBSERVED: an authoritative source directly observed the
    condition (e.g. AWS returned a public ACL grant; a TCP connect
    succeeded). INFERRED: a deterministic correlation supports the
    condition but direct validation is incomplete (owned by M9).
    VALIDATED: explicit canonical validation evidence satisfies a
    defined validation mechanism — NOT implemented as a producing path
    in M8 (no active-validation source exists yet); browser clients
    can never set this directly (see api/v1/security_conditions.py —
    no PATCH/PUT endpoint exists for evidence_state at all)."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    VALIDATED = "validated"


@unique
class SourceCategory(StrEnum):
    """Only categories with a real, currently-wired producing path.

    ACTIVE_VALIDATION (M11): the Gated Safe Active Validation engine
    (`application/validation_execution/`) — real, bounded, non-destructive
    network checks (DNS/TCP/TLS/HTTP) against an authorized canonical
    target, gated by a fresh M10 ExecutionPolicyService decision before
    dispatch. AI_RED_TEAM is still deliberately NOT included — no
    producing source exists for it yet; adding it now would be exactly
    the "roadmap appearance" the milestone forbids."""

    NETWORK_DISCOVERY = "network_discovery"
    CLOUD_CONFIGURATION = "cloud_configuration"
    IDENTITY_ANALYSIS = "identity_analysis"
    MANUAL_IMPORT = "manual_import"
    ACTIVE_VALIDATION = "active_validation"


@unique
class ConditionLifecycle(StrEnum):
    """ACTIVE: last discovery run still observes this condition.
    RESOLVED: explicitly marked resolved via
    `TenantSecurityConditionService.resolve_condition` — never
    automatically flipped merely because one discovery run failed
    (a transient scan error is not evidence the condition is gone)."""

    ACTIVE = "active"
    RESOLVED = "resolved"


class SecurityConditionValidationError(ValueError):
    pass


def build_condition_identity_key(
    organization_id: str,
    affected_asset_id: str,
    source_category: SourceCategory,
    stable_rule_id: str,
    qualifier: str = "",
) -> str:
    """Deterministic deduplication key — organization + affected asset
    + source + stable rule ID + optional qualifier (e.g. a port number
    for a per-port rule). Title/summary/remediation are NEVER part of
    this key — changing them must never create a duplicate condition.
    The same rule on two different assets, or the same CVE-equivalent
    rule ID from two different sources, are always distinct conditions."""
    if not affected_asset_id or not stable_rule_id:
        raise SecurityConditionValidationError(
            "affected_asset_id and stable_rule_id must not be empty"
        )
    return f"{affected_asset_id}:{source_category.value}:{stable_rule_id}:{qualifier}"

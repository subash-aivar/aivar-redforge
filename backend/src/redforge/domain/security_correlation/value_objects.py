"""Value objects for the Security Correlation bounded context — M9.

A SecurityCorrelation is a deterministic relationship between canonical
facts/conditions/entities — distinct from a single `SecurityCondition`
(domain/security_conditions/) and from a validated `Finding`
(domain/findings/). This bounded context does not weaken either — it
adds a third, higher-order truth: "these already-canonical facts
co-occur in a way an operator should review," never "this is
exploitable" or "this asset is compromised."
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class CorrelationLifecycle(StrEnum):
    """ACTIVE: the last successful evaluation cycle still satisfies this
    correlation's rule predicate. RESOLVED: a successful (not merely
    attempted) evaluation cycle no longer satisfies it — never set
    because one fact query failed (see `application/security_correlation/
    service.py`'s evaluation-cycle safety contract)."""

    ACTIVE = "active"
    RESOLVED = "resolved"


@unique
class ExternalExposureClassification(StrEnum):
    """Conservative, precedence-ordered exposure classification. Each
    level is evidence that the previous level's claim does NOT
    automatically extend to the next — a PUBLIC_ADDRESS_OBSERVED asset
    is not thereby PUBLIC_ENDPOINT_CONFIGURED, and none of the first
    four levels imply EXTERNALLY_REACHABLE_VALIDATED, which this
    milestone has no producing validator for and therefore never
    emits."""

    NONE_OBSERVED = "none_observed"
    PUBLIC_ADDRESS_OBSERVED = "public_address_observed"
    PUBLIC_ENDPOINT_CONFIGURED = "public_endpoint_configured"
    BROAD_INGRESS_CONFIGURED = "broad_ingress_configured"
    EXTERNALLY_REACHABLE_VALIDATED = "externally_reachable_validated"


# Explicit precedence — index position, not alphabetical order, decides
# the "strongest" classification when more than one applies to the same
# asset context.
_CLASSIFICATION_PRECEDENCE: tuple[ExternalExposureClassification, ...] = (
    ExternalExposureClassification.NONE_OBSERVED,
    ExternalExposureClassification.PUBLIC_ADDRESS_OBSERVED,
    ExternalExposureClassification.PUBLIC_ENDPOINT_CONFIGURED,
    ExternalExposureClassification.BROAD_INGRESS_CONFIGURED,
    ExternalExposureClassification.EXTERNALLY_REACHABLE_VALIDATED,
)


def strongest_classification(
    classifications: list[ExternalExposureClassification],
) -> ExternalExposureClassification:
    """Selects the strongest classification present, by explicit
    precedence order — never by string/alphabetical sort, and never
    defaulting to the strongest possible value when the input is
    empty."""
    if not classifications:
        return ExternalExposureClassification.NONE_OBSERVED
    return max(classifications, key=_CLASSIFICATION_PRECEDENCE.index)


class SecurityCorrelationValidationError(ValueError):
    pass


def build_correlation_identity_key(
    organization_id: str,
    stable_rule_id: str,
    rule_version: int,
    entity_ids: list[str],
) -> str:
    """Deterministic deduplication key — organization + stable rule ID +
    rule version + a SORTED, deduplicated set of canonical entity IDs.
    Title/summary/operator_action are NEVER part of this key — editing
    them must never fabricate a duplicate correlation. Entity ORDER must
    never matter — the caller may discover the same entities in any
    order across evaluation runs."""
    if not stable_rule_id or not entity_ids:
        raise SecurityCorrelationValidationError(
            "stable_rule_id and entity_ids must not be empty"
        )
    sorted_entities = ",".join(sorted(set(entity_ids)))
    return f"{stable_rule_id}:{rule_version}:{sorted_entities}"

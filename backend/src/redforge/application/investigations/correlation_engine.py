"""Deterministic cross-domain correlation engine — M21.

All correlation decisions are deterministic, explainable, and testable.
No opaque AI/LLM correlation is used as source of truth.

Rules implemented:
  R01 — Same entity, cross domain (two domains, same normalized entity)
  R02 — Related entities (Security Graph relationship proximity) [deferred]
  R03 — Recurrent signal (new evidence matches existing active case)
  R04 — Multi-domain escalation (3+ independent domains)
  R05 — Threat-intel enrichment (TI match + entity in existing case)
  R06 — DDoS + behavioral context (same resource/entity, bounded window)
  R07 — Network security + behavior (same asset, deterministic identity)

Negative invariants (always enforced):
  N01 — Unrelated entities with only timestamp proximity do NOT correlate
  N02 — Different tenants NEVER correlate
  N03 — Duplicate evidence does NOT inflate confidence
"""

from __future__ import annotations

from redforge.domain.investigations.value_objects import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    CorrelationConfidence,
    CorrelationDecision,
    CorrelationRuleId,
    EvidenceCandidate,
    EvidenceObservability,
    NormalizedEntity,
    NormalizedEntityType,
    SourceDomain,
    max_severity,
)

# Current rule versions — bump when a rule's semantics change.
RULE_VERSIONS: dict[CorrelationRuleId, int] = {
    CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN: 1,
    CorrelationRuleId.RELATED_ENTITIES: 1,
    CorrelationRuleId.RECURRENT_SIGNAL: 1,
    CorrelationRuleId.MULTI_DOMAIN_ESCALATION: 1,
    CorrelationRuleId.THREAT_INTEL_ENRICHMENT: 1,
    CorrelationRuleId.DDOS_PLUS_BEHAVIOR: 1,
    CorrelationRuleId.NETWORK_SECURITY_PLUS_BEHAVIOR: 1,
}


def _shared_ip_entities(
    a: EvidenceCandidate, b: EvidenceCandidate
) -> list[NormalizedEntity]:
    """Return normalized entities shared between two candidates.

    Only IP_ADDRESS and RESOURCE entities count as correlation anchors.
    DETECTION entities are used for recurrence, not cross-domain correlation.
    """
    anchor_types = {NormalizedEntityType.IP_ADDRESS, NormalizedEntityType.RESOURCE}
    a_anchors = {e for e in a.normalized_entities if e.entity_type in anchor_types}
    b_anchors = {e for e in b.normalized_entities if e.entity_type in anchor_types}
    return sorted(a_anchors & b_anchors, key=str)


def _within_window(a: EvidenceCandidate, b: EvidenceCandidate, window_seconds: int) -> bool:
    """True if two candidates are within the correlation time window."""
    delta = abs((a.observed_at - b.observed_at).total_seconds())
    return delta <= window_seconds


def evaluate_pair(
    a: EvidenceCandidate,
    b: EvidenceCandidate,
    *,
    window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> CorrelationDecision | None:
    """Evaluate whether two evidence candidates should be correlated.

    Returns a CorrelationDecision if any rule matches, or None if they
    should NOT be correlated.

    Invariant N01: timestamp proximity alone is never sufficient.
    Invariant N02: cross-tenant evidence is rejected before calling this.
    """
    # N02: cross-tenant guard (caller must also enforce, defense in depth)
    if a.organization_id != b.organization_id:
        return None

    # Candidates from the same source domain do not trigger cross-domain rules.
    # They may still create or join a case via RECURRENT_SIGNAL, handled separately.
    if a.source_domain == b.source_domain:
        return None

    shared_entities = _shared_ip_entities(a, b)
    if not shared_entities:
        # No shared canonical entities → no correlation regardless of timing
        # This is N01: timestamps alone are never sufficient.
        return None

    if not _within_window(a, b, window_seconds):
        # Outside correlation window → no correlation
        return None

    # R06 — DDoS + Behavioral Context (specific cross-domain rule)
    domains = {a.source_domain, b.source_domain}
    if domains == {SourceDomain.DDOS, SourceDomain.BEHAVIOR}:
        rule = CorrelationRuleId.DDOS_PLUS_BEHAVIOR
        [str(e) for e in shared_entities]
        reason = (
            f"DDoS incident and behavioral detection share {len(shared_entities)} "
            f"canonical entit{'y' if len(shared_entities) == 1 else 'ies'} "
            f"({', '.join(e.entity_id for e in shared_entities[:3])}) "
            f"within {window_seconds // 3600}h correlation window. "
            "Correlation does not imply causality."
        )
        severity = max_severity(a.severity, b.severity)
        confidence = CorrelationConfidence.HIGH
        return CorrelationDecision(
            rule_id=rule,
            rule_version=RULE_VERSIONS[rule],
            shared_entities=tuple(shared_entities),
            source_domains=(a.source_domain, b.source_domain),
            correlation_window_seconds=window_seconds,
            confidence=confidence,
            severity=severity,
            reason=reason,
            observability=EvidenceObservability.OBSERVED,
        )

    # R01 — Same entity, cross domain (generic)
    rule = CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN
    [str(e) for e in shared_entities]
    reason = (
        f"Independent {a.source_domain.value} and {b.source_domain.value} signals "
        f"affect the same canonical entit{'y' if len(shared_entities) == 1 else 'ies'} "
        f"({', '.join(e.entity_id for e in shared_entities[:3])}) "
        f"within the {window_seconds // 3600}h correlation window."
    )
    severity = max_severity(a.severity, b.severity)
    confidence = CorrelationConfidence.HIGH

    return CorrelationDecision(
        rule_id=rule,
        rule_version=RULE_VERSIONS[rule],
        shared_entities=tuple(shared_entities),
        source_domains=(a.source_domain, b.source_domain),
        correlation_window_seconds=window_seconds,
        confidence=confidence,
        severity=severity,
        reason=reason,
        observability=EvidenceObservability.OBSERVED,
    )


def evaluate_recurrence(
    new_candidate: EvidenceCandidate,
    existing_case_entity_ids: list[str],
    existing_case_source_domains: list[str],
    existing_case_domain_count: int,
    *,
    window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> CorrelationDecision | None:
    """R03 — Recurrent signal: new evidence joins an existing active case.

    The new candidate shares at least one anchor entity with the existing case.
    """
    anchor_types = {NormalizedEntityType.IP_ADDRESS, NormalizedEntityType.RESOURCE}
    candidate_anchors = {
        str(e)
        for e in new_candidate.normalized_entities
        if e.entity_type in anchor_types
    }

    shared = candidate_anchors & set(existing_case_entity_ids)
    if not shared:
        return None

    is_new_domain = (
        new_candidate.source_domain.value not in existing_case_source_domains
    )
    total_domains = existing_case_domain_count + (1 if is_new_domain else 0)

    if total_domains >= 3:
        rule = CorrelationRuleId.MULTI_DOMAIN_ESCALATION
        confidence = CorrelationConfidence.VERY_HIGH
        reason = (
            f"New {new_candidate.source_domain.value} evidence joins an investigation "
            f"already spanning {existing_case_domain_count} domain(s). "
            f"Total of {total_domains} independent domains now corroborate "
            f"the same {len(shared)} canonical entit{'y' if len(shared) == 1 else 'ies'}."
        )
    elif is_new_domain:
        rule = CorrelationRuleId.RECURRENT_SIGNAL
        confidence = CorrelationConfidence.HIGH
        reason = (
            f"New {new_candidate.source_domain.value} evidence shares "
            f"{len(shared)} canonical entit{'y' if len(shared) == 1 else 'ies'} "
            "with an existing active investigation from a different source domain."
        )
    else:
        rule = CorrelationRuleId.RECURRENT_SIGNAL
        confidence = CorrelationConfidence.MEDIUM
        reason = (
            f"New {new_candidate.source_domain.value} evidence shares "
            f"{len(shared)} canonical entit{'y' if len(shared) == 1 else 'ies'} "
            "with an existing active investigation."
        )

    shared_entities_parsed = [
        NormalizedEntity(
            entity_type=NormalizedEntityType(s.split(":")[0]),
            entity_id=s.split(":", 1)[1],
        )
        for s in sorted(shared)
    ]

    return CorrelationDecision(
        rule_id=rule,
        rule_version=RULE_VERSIONS[rule],
        shared_entities=tuple(shared_entities_parsed),
        source_domains=(new_candidate.source_domain,),
        correlation_window_seconds=window_seconds,
        confidence=confidence,
        severity=new_candidate.severity,
        reason=reason,
        observability=EvidenceObservability.OBSERVED,
    )


def compute_case_confidence(
    domain_count: int,
    evidence_count: int,
    has_threat_intel: bool,
) -> CorrelationConfidence:
    """Compute case confidence from deterministic criteria.

    Confidence criteria (monotonic — never decreases from evidence count alone):
    - VERY_HIGH: 3+ independent domains, OR 2+ domains + threat-intel
    - HIGH: exactly 2 independent domains
    - MEDIUM: 1 domain, multiple evidence items (recurrence)
    - LOW: 1 domain, 1 evidence item
    """
    if domain_count >= 3 or (domain_count >= 2 and has_threat_intel):
        return CorrelationConfidence.VERY_HIGH
    if domain_count >= 2:
        return CorrelationConfidence.HIGH
    if evidence_count >= 3:
        return CorrelationConfidence.MEDIUM
    return CorrelationConfidence.LOW


def generate_case_title(
    decision: CorrelationDecision,
    source_entity_labels: list[str],
) -> str:
    """Generate a deterministic, human-readable case title.

    Title is for display only — never part of the correlation key.
    """
    domains_str = " + ".join(
        sorted(d.value.title().replace("_", " ") for d in decision.source_domains)
    )
    entity_labels = source_entity_labels[:2]
    entity_str = ", ".join(entity_labels) if entity_labels else "unknown entity"

    if decision.rule_id == CorrelationRuleId.DDOS_PLUS_BEHAVIOR:
        return f"DDoS + Behavioral Anomaly: {entity_str}"
    if decision.rule_id == CorrelationRuleId.MULTI_DOMAIN_ESCALATION:
        return f"Multi-Domain Threat: {entity_str}"
    if decision.rule_id == CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN:
        return f"Cross-Domain Detection: {entity_str}"
    if decision.rule_id == CorrelationRuleId.RECURRENT_SIGNAL:
        return f"Recurring Signal: {entity_str}"

    return f"Security Investigation: {entity_str} ({domains_str})"


def generate_case_summary(decision: CorrelationDecision) -> str:
    """Generate a deterministic case summary from the correlation decision."""
    entity_count = len(decision.shared_entities)
    domain_count = len(set(decision.source_domains))
    return (
        f"{domain_count} independent security domain(s) report related activity "
        f"affecting {entity_count} shared entit{'y' if entity_count == 1 else 'ies'}. "
        f"{decision.reason}"
    )

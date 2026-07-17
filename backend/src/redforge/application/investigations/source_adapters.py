"""Source domain adapters — M21.

Each adapter translates a source-domain row into a typed EvidenceCandidate.

Adapter contract:
- Typed output (no untyped dict soup)
- Normalized entities only from deterministic identity resolution
- Stable dedup_key: same row always produces the same key
- No I/O: adapters are pure translation functions
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from redforge.domain.investigations.value_objects import (
    EvidenceCandidate,
    InvestigationSeverity,
    NormalizedEntity,
    NormalizedEntityType,
    SourceDomain,
    normalize_ip,
    normalize_resource_id,
)

# ── Severity mapping ──────────────────────────────────────────────────────────

_DDOS_SEVERITY_MAP: dict[str, InvestigationSeverity] = {
    "CRITICAL": InvestigationSeverity.CRITICAL,
    "HIGH": InvestigationSeverity.HIGH,
    "MEDIUM": InvestigationSeverity.MEDIUM,
    "LOW": InvestigationSeverity.LOW,
}

_BEHAVIOR_SEVERITY_MAP: dict[str, InvestigationSeverity] = {
    "CRITICAL": InvestigationSeverity.CRITICAL,
    "HIGH": InvestigationSeverity.HIGH,
    "MEDIUM": InvestigationSeverity.MEDIUM,
    "LOW": InvestigationSeverity.LOW,
    "INFORMATIONAL": InvestigationSeverity.LOW,
}

_DEFAULT_SEVERITY = InvestigationSeverity.MEDIUM


def _map_ddos_severity(raw: str) -> InvestigationSeverity:
    return _DDOS_SEVERITY_MAP.get(raw.upper(), _DEFAULT_SEVERITY)


def _map_behavior_severity(raw: str) -> InvestigationSeverity:
    return _BEHAVIOR_SEVERITY_MAP.get(raw.upper(), _DEFAULT_SEVERITY)


# ── M19 DDoS Incident Adapter ─────────────────────────────────────────────────


def adapt_ddos_incident(
    org_id: str,
    incident_id: str,
    resource_id: str,
    resource_name: str,
    scope_type: str,
    scope_value: str | None,
    severity: str,
    status: str,
    attack_classification: str,
    opening_evidence: dict[str, Any],
    detected_at: datetime,
) -> EvidenceCandidate | None:
    """Translate a DDoS incident into a correlation candidate.

    Returns None if entity normalization fails (no canonical entity).
    Only OPEN/ACTIVE/ESCALATED incidents are processed — terminal ones
    are ignored unless needed for recurrence tracking.
    """
    terminal_statuses = {"RESOLVED", "CLOSED"}
    if status.upper() in terminal_statuses:
        return None

    # Normalize entities: the protected resource is the primary entity
    entities: list[NormalizedEntity] = []

    resource_entity = normalize_resource_id(resource_id)
    if resource_entity:
        entities.append(resource_entity)

    # If scope is an IP address, also add that as a secondary entity
    if scope_type == "cidr" and scope_value:
        ip_part = scope_value.split("/")[0] if "/" in scope_value else scope_value
        ip_entity = normalize_ip(ip_part)
        if ip_entity:
            entities.append(ip_entity)

    if not entities:
        return None

    inv_severity = _map_ddos_severity(severity)

    # Extract known source IPs from opening evidence for entity correlation
    source_ips: list[str] = opening_evidence.get("top_source_ips", [])
    for raw_ip in source_ips[:5]:  # limit to top 5 to bound entity list
        ip_entity = normalize_ip(str(raw_ip))
        if ip_entity:
            entities.append(ip_entity)

    snapshot: dict[str, object] = {
        "resource_id": resource_id,
        "resource_name": resource_name,
        "attack_classification": attack_classification,
        "severity": severity,
        "status": status,
        "scope_type": scope_type,
        "scope_value": scope_value,
    }

    return EvidenceCandidate(
        organization_id=org_id,
        source_domain=SourceDomain.DDOS,
        source_entity_type="ddos_incident",
        source_entity_id=incident_id,
        event_type="INCIDENT_ACTIVE",
        severity=inv_severity,
        observed_at=detected_at,
        normalized_entities=tuple(entities),
        evidence_snapshot=snapshot,
        dedup_key=f"ddos:incident:{incident_id}",
    )


# ── M20 Behavioral Detection Adapter ─────────────────────────────────────────


def adapt_behavior_detection(
    org_id: str,
    detection_id: str,
    correlation_key: str,
    entity_type: str,
    entity_id: str,
    detection_type: str,
    severity: str,
    status: str,
    evidence: dict[str, Any],
    secondary_entity_id: str | None,
    detected_at: datetime,
) -> EvidenceCandidate | None:
    """Translate a behavioral detection into a correlation candidate.

    Returns None if entity normalization fails.
    """
    terminal_statuses = {"RESOLVED", "CLOSED"}
    if status.upper() in terminal_statuses:
        return None

    entities: list[NormalizedEntity] = []

    if entity_type == "IP_ADDRESS":
        ip_entity = normalize_ip(entity_id)
        if ip_entity:
            entities.append(ip_entity)
    elif entity_type == "COMMUNICATION_PAIR" and secondary_entity_id:
        ip1 = normalize_ip(entity_id)
        ip2 = normalize_ip(secondary_entity_id)
        if ip1:
            entities.append(ip1)
        if ip2:
            entities.append(ip2)

    # Also add the detection itself as a DETECTION entity for recurrence tracking
    entities.append(
        NormalizedEntity(
            entity_type=NormalizedEntityType.DETECTION,
            entity_id=correlation_key,
        )
    )

    if not any(
        e.entity_type != NormalizedEntityType.DETECTION for e in entities
    ):
        return None

    inv_severity = _map_behavior_severity(severity)

    snapshot: dict[str, object] = {
        "detection_id": detection_id,
        "correlation_key": correlation_key,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "detection_type": detection_type,
        "severity": severity,
        "status": status,
        "secondary_entity_id": secondary_entity_id,
    }

    return EvidenceCandidate(
        organization_id=org_id,
        source_domain=SourceDomain.BEHAVIOR,
        source_entity_type="behavior_detection",
        source_entity_id=detection_id,
        event_type="DETECTION_ACTIVE",
        severity=inv_severity,
        observed_at=detected_at,
        normalized_entities=tuple(entities),
        evidence_snapshot=snapshot,
        dedup_key=f"behavior:detection:{detection_id}",
    )


# ── M22 Phase 6 — Threat Intel Enrichment Adapter ────────────────────────────

_TI_EVIDENCE_KINDS = frozenset({"reputation", "ioc_match"})


def _map_ti_severity(
    *,
    kind: str,
    confidence_score: float | None,
    success: bool,
) -> InvestigationSeverity:
    if not success:
        return InvestigationSeverity.LOW
    if kind == "ioc_match":
        return InvestigationSeverity.HIGH
    if confidence_score is None:
        return InvestigationSeverity.MEDIUM
    if confidence_score >= 75:
        return InvestigationSeverity.HIGH
    if confidence_score >= 40:
        return InvestigationSeverity.MEDIUM
    return InvestigationSeverity.LOW


def adapt_threat_intel_enrichment(
    org_id: str,
    *,
    indicator_id: str,
    indicator: str,
    indicator_type: str,
    enrichment_id: str,
    provider_name: str,
    kind: str,
    success: bool,
    data: dict[str, Any],
    fetched_at: datetime,
    expires_at: datetime,
    now: datetime | None = None,
) -> EvidenceCandidate | None:
    """Translate a fresh, successful threat-intel enrichment into a candidate.

    Hardening / freeze constraints:
    - Expired enrichments are refused as investigation evidence (staleness gate).
    - Only reputation / ioc_match kinds are correlation-eligible.
    - Adapter lives in the investigations application layer (ACL) and emits
      investigations-domain `EvidenceCandidate` only — no threat_intel domain
      imports.
    """
    clock = now or datetime.now(UTC)
    expires = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=UTC)
    if expires <= clock:
        return None
    if not success:
        return None
    if kind not in _TI_EVIDENCE_KINDS:
        return None

    entities: list[NormalizedEntity] = []
    if indicator_type.lower() == "ip":
        ip_entity = normalize_ip(indicator)
        if ip_entity:
            entities.append(ip_entity)
    if not entities:
        return None

    confidence_score = data.get("confidence_score")
    score: float | None
    try:
        score = float(confidence_score) if confidence_score is not None else None
    except (TypeError, ValueError):
        score = None

    severity = _map_ti_severity(
        kind=kind, confidence_score=score, success=success
    )
    snapshot: dict[str, object] = {
        "indicator_id": indicator_id,
        "indicator": indicator,
        "indicator_type": indicator_type,
        "provider_name": provider_name,
        "kind": kind,
        "confidence_score": score,
        "fetched_at": fetched_at.isoformat(),
        "expires_at": expires.isoformat(),
    }
    return EvidenceCandidate(
        organization_id=org_id,
        source_domain=SourceDomain.THREAT_INTEL,
        source_entity_type="threat_intel_enrichment",
        source_entity_id=enrichment_id,
        event_type="ENRICHMENT_FRESH",
        severity=severity,
        observed_at=fetched_at if fetched_at.tzinfo else fetched_at.replace(tzinfo=UTC),
        normalized_entities=tuple(entities),
        evidence_snapshot=snapshot,
        dedup_key=f"threat_intel:enrichment:{enrichment_id}",
    )

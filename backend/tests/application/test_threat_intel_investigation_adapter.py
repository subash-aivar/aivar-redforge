"""M22 Phase 6 — Threat Intel investigation adapter + R05 correlation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from redforge.application.investigations.correlation_engine import (
    evaluate_pair,
    generate_case_title,
)
from redforge.application.investigations.source_adapters import (
    adapt_behavior_detection,
    adapt_threat_intel_enrichment,
)
from redforge.domain.investigations.value_objects import (
    CorrelationRuleId,
    InvestigationSeverity,
    SourceDomain,
)


def _fresh_expires() -> datetime:
    return datetime.now(UTC) + timedelta(hours=2)


def test_adapt_threat_intel_rejects_expired() -> None:
    candidate = adapt_threat_intel_enrichment(
        "01ORG000000000000000000001",
        indicator_id="01IND000000000000000000001",
        indicator="203.0.113.10",
        indicator_type="ip",
        enrichment_id="01ENR000000000000000000001",
        provider_name="abuseipdb",
        kind="reputation",
        success=True,
        data={"confidence_score": 90},
        fetched_at=datetime.now(UTC) - timedelta(days=2),
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    assert candidate is None


def test_adapt_threat_intel_accepts_fresh_reputation() -> None:
    candidate = adapt_threat_intel_enrichment(
        "01ORG000000000000000000001",
        indicator_id="01IND000000000000000000001",
        indicator="203.0.113.10",
        indicator_type="ip",
        enrichment_id="01ENR000000000000000000001",
        provider_name="abuseipdb",
        kind="reputation",
        success=True,
        data={"confidence_score": 80},
        fetched_at=datetime.now(UTC),
        expires_at=_fresh_expires(),
    )
    assert candidate is not None
    assert candidate.source_domain is SourceDomain.THREAT_INTEL
    assert candidate.severity is InvestigationSeverity.HIGH
    assert candidate.normalized_entities[0].entity_id == "203.0.113.10"


def test_adapt_threat_intel_rejects_geo_kind() -> None:
    candidate = adapt_threat_intel_enrichment(
        "01ORG000000000000000000001",
        indicator_id="01IND000000000000000000001",
        indicator="203.0.113.10",
        indicator_type="ip",
        enrichment_id="01ENR000000000000000000001",
        provider_name="maxmind",
        kind="geolocation",
        success=True,
        data={},
        fetched_at=datetime.now(UTC),
        expires_at=_fresh_expires(),
    )
    assert candidate is None


def test_r05_fires_for_ti_plus_behavior() -> None:
    org = "01ORG000000000000000000001"
    ti = adapt_threat_intel_enrichment(
        org,
        indicator_id="01IND000000000000000000001",
        indicator="203.0.113.55",
        indicator_type="ip",
        enrichment_id="01ENR000000000000000000001",
        provider_name="abuseipdb",
        kind="reputation",
        success=True,
        data={"confidence_score": 70},
        fetched_at=datetime.now(UTC),
        expires_at=_fresh_expires(),
    )
    assert ti is not None
    beh = adapt_behavior_detection(
        org_id=org,
        detection_id="01DET000000000000000000001",
        correlation_key="beh-1",
        entity_type="IP_ADDRESS",
        entity_id="203.0.113.55",
        detection_type="C2",
        severity="HIGH",
        status="OPEN",
        evidence={},
        secondary_entity_id=None,
        detected_at=datetime.now(UTC),
    )
    assert beh is not None
    decision = evaluate_pair(ti, beh)
    assert decision is not None
    assert decision.rule_id is CorrelationRuleId.THREAT_INTEL_ENRICHMENT
    assert "Threat Intel" in generate_case_title(decision, ["203.0.113.55"])

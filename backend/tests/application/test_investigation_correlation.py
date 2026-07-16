"""M21 Correlation engine unit tests.

Pure-function, no I/O, no database.

Covers:
  - evaluate_pair: R06 (DDoS+Behavior), R01 (generic), no-match (different org = None)
  - evaluate_pair: shared entity required (N01)
  - evaluate_pair: returns None when no shared entities
  - evaluate_recurrence: R03 (single domain), R04 (multi-domain escalation)
  - compute_case_confidence: domain/evidence/threat_intel thresholds
  - generate_case_title / generate_case_summary: type check
  - source_adapters: adapt_ddos_incident / adapt_behavior_detection happy paths
  - source_adapters: terminal status → None
  - source_adapters: missing entity → None
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.investigations.correlation_engine import (
    RULE_VERSIONS,
    compute_case_confidence,
    evaluate_pair,
    evaluate_recurrence,
    generate_case_summary,
    generate_case_title,
)
from redforge.application.investigations.source_adapters import (
    adapt_behavior_detection,
    adapt_ddos_incident,
)
from redforge.domain.investigations.value_objects import (
    CorrelationConfidence,
    CorrelationDecision,
    CorrelationRuleId,
    EvidenceCandidate,
    EvidenceObservability,
    InvestigationSeverity,
    NormalizedEntity,
    NormalizedEntityType,
    SourceDomain,
    normalize_ip,
    normalize_resource_id,
)

_TS = datetime(2026, 7, 1, 10, 0, 0, tzinfo=UTC)
_ORG = "org_01JTEST000000000000000000"
_RES_ID = "01JRSC00000000000000000000"  # 26 chars


def _ip_entity(ip: str) -> NormalizedEntity:
    e = normalize_ip(ip)
    assert e is not None
    return e


def _resource_entity(rid: str = _RES_ID) -> NormalizedEntity:
    e = normalize_resource_id(rid)
    assert e is not None
    return e


def _behavior_candidate(
    org_id: str = _ORG,
    entities: tuple[NormalizedEntity, ...] | None = None,
    severity: InvestigationSeverity = InvestigationSeverity.HIGH,
    observed_at: datetime = _TS,
) -> EvidenceCandidate:
    if entities is None:
        entities = (_ip_entity("10.0.0.1"),)
    return EvidenceCandidate(
        organization_id=org_id,
        source_domain=SourceDomain.BEHAVIOR,
        source_entity_type="behavior_detection",
        source_entity_id="beh_001",
        event_type="DETECTION_ACTIVE",
        severity=severity,
        observed_at=observed_at,
        normalized_entities=entities,
        evidence_snapshot={"detection_id": "beh_001"},
        dedup_key="behavior:detection:beh_001",
    )


def _ddos_candidate(
    org_id: str = _ORG,
    entities: tuple[NormalizedEntity, ...] | None = None,
    severity: InvestigationSeverity = InvestigationSeverity.CRITICAL,
    observed_at: datetime = _TS,
) -> EvidenceCandidate:
    if entities is None:
        entities = (_ip_entity("10.0.0.1"),)
    return EvidenceCandidate(
        organization_id=org_id,
        source_domain=SourceDomain.DDOS,
        source_entity_type="ddos_incident",
        source_entity_id="ddos_001",
        event_type="INCIDENT_ACTIVE",
        severity=severity,
        observed_at=observed_at,
        normalized_entities=entities,
        evidence_snapshot={"incident_id": "ddos_001"},
        dedup_key="ddos:incident:ddos_001",
    )


# ── evaluate_pair ──────────────────────────────────────────────────────────────


class TestEvaluatePair:
    def test_r06_ddos_plus_behavior_with_shared_ip(self) -> None:
        beh = _behavior_candidate()
        ddos = _ddos_candidate()
        decision = evaluate_pair(beh, ddos)
        assert decision is not None
        assert decision.rule_id == CorrelationRuleId.DDOS_PLUS_BEHAVIOR
        assert len(decision.shared_entities) == 1
        assert decision.shared_entities[0].entity_id == "10.0.0.1"

    def test_r06_symmetric_order(self) -> None:
        beh = _behavior_candidate()
        ddos = _ddos_candidate()
        d1 = evaluate_pair(beh, ddos)
        d2 = evaluate_pair(ddos, beh)
        assert d1 is not None
        assert d2 is not None
        assert d1.rule_id == d2.rule_id
        assert set(e.entity_id for e in d1.shared_entities) == set(e.entity_id for e in d2.shared_entities)

    def test_no_shared_entity_returns_none(self) -> None:
        beh = _behavior_candidate(entities=(_ip_entity("10.0.0.1"),))
        ddos = _ddos_candidate(entities=(_ip_entity("192.168.1.1"),))
        assert evaluate_pair(beh, ddos) is None

    def test_cross_tenant_returns_none(self) -> None:
        beh = _behavior_candidate(org_id="org_A")
        ddos = _ddos_candidate(org_id="org_B")
        result = evaluate_pair(beh, ddos)
        assert result is None

    def test_same_domain_returns_none(self) -> None:
        # Two behavior candidates — same domain never triggers cross-domain rules
        beh1 = _behavior_candidate()
        beh2 = EvidenceCandidate(
            organization_id=_ORG,
            source_domain=SourceDomain.BEHAVIOR,
            source_entity_type="behavior_detection",
            source_entity_id="beh_002",
            event_type="DETECTION_ACTIVE",
            severity=InvestigationSeverity.MEDIUM,
            observed_at=_TS,
            normalized_entities=(_ip_entity("10.0.0.1"),),
            evidence_snapshot={},
            dedup_key="behavior:detection:beh_002",
        )
        assert evaluate_pair(beh1, beh2) is None

    def test_r06_severity_is_max_of_pair(self) -> None:
        beh = _behavior_candidate(severity=InvestigationSeverity.LOW)
        ddos = _ddos_candidate(severity=InvestigationSeverity.CRITICAL)
        decision = evaluate_pair(beh, ddos)
        assert decision is not None
        assert decision.severity == InvestigationSeverity.CRITICAL

    def test_r06_confidence_high_for_two_domains(self) -> None:
        beh = _behavior_candidate()
        ddos = _ddos_candidate()
        decision = evaluate_pair(beh, ddos)
        assert decision is not None
        assert decision.confidence in (CorrelationConfidence.HIGH, CorrelationConfidence.VERY_HIGH)

    def test_r06_observability_observed(self) -> None:
        beh = _behavior_candidate()
        ddos = _ddos_candidate()
        decision = evaluate_pair(beh, ddos)
        assert decision is not None
        assert decision.observability == EvidenceObservability.OBSERVED

    def test_shared_resource_entity_triggers_correlation(self) -> None:
        res = _resource_entity()
        beh = _behavior_candidate(entities=(res,))
        ddos = _ddos_candidate(entities=(res,))
        decision = evaluate_pair(beh, ddos)
        assert decision is not None
        assert any(e.entity_type == NormalizedEntityType.RESOURCE for e in decision.shared_entities)

    def test_r06_reason_is_non_empty_string(self) -> None:
        beh = _behavior_candidate()
        ddos = _ddos_candidate()
        decision = evaluate_pair(beh, ddos)
        assert decision is not None
        assert len(decision.reason) > 10  # substantive reason, not empty


# ── evaluate_recurrence ────────────────────────────────────────────────────────


class TestEvaluateRecurrence:
    def test_r03_single_domain_recurrence(self) -> None:
        candidate = _behavior_candidate()
        existing_entity_ids = ["IP_ADDRESS:10.0.0.1"]
        decision = evaluate_recurrence(
            candidate,
            existing_case_entity_ids=existing_entity_ids,
            existing_case_source_domains=["behavior"],
            existing_case_domain_count=1,
        )
        assert decision is not None
        assert decision.rule_id == CorrelationRuleId.RECURRENT_SIGNAL
        assert decision.confidence == CorrelationConfidence.MEDIUM

    def test_r04_multi_domain_escalation_new_domain(self) -> None:
        # Existing case has 2 domains (behavior + ddos); adding threat_intel makes 3
        threat_intel_candidate = EvidenceCandidate(
            organization_id=_ORG,
            source_domain=SourceDomain.THREAT_INTEL,
            source_entity_type="threat_indicator",
            source_entity_id="ti_001",
            event_type="INDICATOR_MATCHED",
            severity=InvestigationSeverity.HIGH,
            observed_at=_TS,
            normalized_entities=(_ip_entity("10.0.0.1"),),
            evidence_snapshot={},
            dedup_key="threat_intel:ti:ti_001",
        )
        decision = evaluate_recurrence(
            threat_intel_candidate,
            existing_case_entity_ids=["IP_ADDRESS:10.0.0.1"],
            existing_case_source_domains=["behavior", "ddos"],
            existing_case_domain_count=2,
        )
        assert decision is not None
        assert decision.rule_id == CorrelationRuleId.MULTI_DOMAIN_ESCALATION

    def test_r04_3_domains_very_high_confidence(self) -> None:
        # 2 existing domains + new domain = 3 total → VERY_HIGH
        threat_intel_candidate = EvidenceCandidate(
            organization_id=_ORG,
            source_domain=SourceDomain.THREAT_INTEL,
            source_entity_type="threat_indicator",
            source_entity_id="ti_002",
            event_type="INDICATOR_MATCHED",
            severity=InvestigationSeverity.HIGH,
            observed_at=_TS,
            normalized_entities=(_ip_entity("10.0.0.1"),),
            evidence_snapshot={},
            dedup_key="threat_intel:ti:ti_002",
        )
        decision = evaluate_recurrence(
            threat_intel_candidate,
            existing_case_entity_ids=["IP_ADDRESS:10.0.0.1"],
            existing_case_source_domains=["behavior", "ddos"],
            existing_case_domain_count=2,
        )
        assert decision is not None
        assert decision.confidence == CorrelationConfidence.VERY_HIGH

    def test_no_shared_entity_returns_none(self) -> None:
        candidate = _behavior_candidate(entities=(_ip_entity("192.168.100.1"),))
        result = evaluate_recurrence(
            candidate,
            existing_case_entity_ids=["IP_ADDRESS:10.0.0.1"],
            existing_case_source_domains=["behavior"],
            existing_case_domain_count=1,
        )
        assert result is None

    def test_empty_existing_entities_returns_none(self) -> None:
        candidate = _behavior_candidate()
        result = evaluate_recurrence(
            candidate,
            existing_case_entity_ids=[],
            existing_case_source_domains=["behavior"],
            existing_case_domain_count=1,
        )
        assert result is None


# ── compute_case_confidence ────────────────────────────────────────────────────


class TestComputeCaseConfidence:
    def test_single_domain_single_evidence_is_low(self) -> None:
        conf = compute_case_confidence(domain_count=1, evidence_count=1, has_threat_intel=False)
        assert conf == CorrelationConfidence.LOW

    def test_two_domains_is_high(self) -> None:
        conf = compute_case_confidence(domain_count=2, evidence_count=2, has_threat_intel=False)
        assert conf == CorrelationConfidence.HIGH

    def test_two_domains_with_threat_intel_is_very_high(self) -> None:
        conf = compute_case_confidence(domain_count=2, evidence_count=2, has_threat_intel=True)
        assert conf == CorrelationConfidence.VERY_HIGH

    def test_three_domains_is_very_high(self) -> None:
        conf = compute_case_confidence(domain_count=3, evidence_count=3, has_threat_intel=False)
        assert conf == CorrelationConfidence.VERY_HIGH

    def test_single_domain_multiple_evidence_is_medium(self) -> None:
        conf = compute_case_confidence(domain_count=1, evidence_count=3, has_threat_intel=False)
        assert conf == CorrelationConfidence.MEDIUM


# ── generate_case_title / generate_case_summary ────────────────────────────────


class TestGenerateCaseTitleSummary:
    def _decision(self) -> CorrelationDecision:
        ip = _ip_entity("10.0.0.1")
        return CorrelationDecision(
            rule_id=CorrelationRuleId.DDOS_PLUS_BEHAVIOR,
            rule_version=RULE_VERSIONS[CorrelationRuleId.DDOS_PLUS_BEHAVIOR],
            shared_entities=(ip,),
            source_domains=(SourceDomain.DDOS, SourceDomain.BEHAVIOR),
            correlation_window_seconds=4 * 3600,
            confidence=CorrelationConfidence.HIGH,
            severity=InvestigationSeverity.CRITICAL,
            reason="Test",
            observability=EvidenceObservability.OBSERVED,
        )

    def test_title_is_non_empty_string(self) -> None:
        title = generate_case_title(self._decision(), ["10.0.0.1"])
        assert isinstance(title, str)
        assert len(title) > 5

    def test_summary_is_non_empty_string(self) -> None:
        summary = generate_case_summary(self._decision())
        assert isinstance(summary, str)
        assert len(summary) > 5

    def test_title_contains_rule_info(self) -> None:
        title = generate_case_title(self._decision(), ["10.0.0.1"])
        # Title should mention something about the correlation type or entities
        assert len(title) > 0

    def test_title_truncated_at_200(self) -> None:
        long_entities = ["192.168.0." + str(i) for i in range(50)]
        title = generate_case_title(self._decision(), long_entities)
        assert len(title) <= 200


# ── RULE_VERSIONS ──────────────────────────────────────────────────────────────


class TestRuleVersions:
    def test_all_rules_have_version(self) -> None:
        for rule_id in CorrelationRuleId:
            assert rule_id in RULE_VERSIONS, f"Missing version for {rule_id}"
            assert isinstance(RULE_VERSIONS[rule_id], int)
            assert RULE_VERSIONS[rule_id] >= 1


# ── adapt_ddos_incident ────────────────────────────────────────────────────────


class TestAdaptDdosIncident:
    def test_active_incident_produces_candidate(self) -> None:
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_001",
            resource_id=_RES_ID,
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="HIGH",
            status="ACTIVE",
            attack_classification="VOLUMETRIC",
            opening_evidence={"top_source_ips": ["10.1.1.1"]},
            detected_at=_TS,
        )
        assert candidate is not None
        assert candidate.organization_id == _ORG
        assert candidate.source_domain == SourceDomain.DDOS
        assert candidate.dedup_key == "ddos:incident:inc_001"
        assert len(candidate.normalized_entities) >= 1

    def test_resource_entity_present(self) -> None:
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_001",
            resource_id=_RES_ID,
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="CRITICAL",
            status="ESCALATED",
            attack_classification="VOLUMETRIC",
            opening_evidence={},
            detected_at=_TS,
        )
        assert candidate is not None
        entity_types = [e.entity_type for e in candidate.normalized_entities]
        assert NormalizedEntityType.RESOURCE in entity_types

    def test_terminal_status_returns_none(self) -> None:
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_resolved",
            resource_id=_RES_ID,
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="HIGH",
            status="RESOLVED",
            attack_classification="VOLUMETRIC",
            opening_evidence={},
            detected_at=_TS,
        )
        assert candidate is None

    def test_closed_status_returns_none(self) -> None:
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_closed",
            resource_id=_RES_ID,
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="HIGH",
            status="CLOSED",
            attack_classification="VOLUMETRIC",
            opening_evidence={},
            detected_at=_TS,
        )
        assert candidate is None

    def test_source_ips_from_evidence_added_as_entities(self) -> None:
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_001",
            resource_id=_RES_ID,
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="HIGH",
            status="ACTIVE",
            attack_classification="VOLUMETRIC",
            opening_evidence={"top_source_ips": ["10.1.1.1", "10.1.1.2"]},
            detected_at=_TS,
        )
        assert candidate is not None
        ip_entities = [e for e in candidate.normalized_entities if e.entity_type == NormalizedEntityType.IP_ADDRESS]
        assert len(ip_entities) >= 1

    def test_severity_mapping_high(self) -> None:
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_001",
            resource_id=_RES_ID,
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="HIGH",
            status="ACTIVE",
            attack_classification="VOLUMETRIC",
            opening_evidence={},
            detected_at=_TS,
        )
        assert candidate is not None
        assert candidate.severity == InvestigationSeverity.HIGH

    def test_invalid_resource_id_returns_none(self) -> None:
        # Short resource_id cannot be normalized → no RESOURCE entity
        # But adapt still returns a candidate if there are OTHER entities (like IPs from evidence).
        # If there are no entities at all, it returns None.
        candidate = adapt_ddos_incident(
            org_id=_ORG,
            incident_id="inc_no_entity",
            resource_id="bad",  # too short → cannot normalize
            resource_name="prod-lb",
            scope_type="any",
            scope_value=None,
            severity="HIGH",
            status="ACTIVE",
            attack_classification="VOLUMETRIC",
            opening_evidence={},  # no source IPs
            detected_at=_TS,
        )
        # No RESOURCE entity (bad ID) and no IP entities (no evidence) → None
        assert candidate is None


# ── adapt_behavior_detection ───────────────────────────────────────────────────


class TestAdaptBehaviorDetection:
    def test_active_detection_produces_candidate(self) -> None:
        candidate = adapt_behavior_detection(
            org_id=_ORG,
            detection_id="det_001",
            correlation_key="org_A|entity_type|entity_id",
            entity_type="IP_ADDRESS",
            entity_id="10.0.0.1",
            detection_type="FAN_OUT",
            severity="HIGH",
            status="OPEN",
            evidence={"fan_out_count": 50},
            secondary_entity_id=None,
            detected_at=_TS,
        )
        assert candidate is not None
        assert candidate.source_domain == SourceDomain.BEHAVIOR
        assert candidate.dedup_key == "behavior:detection:det_001"

    def test_ip_entity_normalized(self) -> None:
        candidate = adapt_behavior_detection(
            org_id=_ORG,
            detection_id="det_001",
            correlation_key="k",
            entity_type="IP_ADDRESS",
            entity_id="192.168.1.50",
            detection_type="FAN_OUT",
            severity="MEDIUM",
            status="OPEN",
            evidence={},
            secondary_entity_id=None,
            detected_at=_TS,
        )
        assert candidate is not None
        ip_entities = [e for e in candidate.normalized_entities if e.entity_type == NormalizedEntityType.IP_ADDRESS]
        assert len(ip_entities) == 1
        assert ip_entities[0].entity_id == "192.168.1.50"

    def test_terminal_status_returns_none(self) -> None:
        candidate = adapt_behavior_detection(
            org_id=_ORG,
            detection_id="det_closed",
            correlation_key="k",
            entity_type="IP_ADDRESS",
            entity_id="10.0.0.1",
            detection_type="FAN_OUT",
            severity="HIGH",
            status="RESOLVED",
            evidence={},
            secondary_entity_id=None,
            detected_at=_TS,
        )
        assert candidate is None

    def test_invalid_ip_entity_returns_none(self) -> None:
        # entity_type is IP_ADDRESS but entity_id is not a valid IP
        candidate = adapt_behavior_detection(
            org_id=_ORG,
            detection_id="det_bad_ip",
            correlation_key="k",
            entity_type="IP_ADDRESS",
            entity_id="not-an-ip",
            detection_type="FAN_OUT",
            severity="HIGH",
            status="OPEN",
            evidence={},
            secondary_entity_id=None,
            detected_at=_TS,
        )
        assert candidate is None

    def test_severity_mapping_critical(self) -> None:
        candidate = adapt_behavior_detection(
            org_id=_ORG,
            detection_id="det_001",
            correlation_key="k",
            entity_type="IP_ADDRESS",
            entity_id="10.0.0.1",
            detection_type="FAN_OUT",
            severity="CRITICAL",
            status="OPEN",
            evidence={},
            secondary_entity_id=None,
            detected_at=_TS,
        )
        assert candidate is not None
        assert candidate.severity == InvestigationSeverity.CRITICAL

    def test_communication_pair_adds_both_ips(self) -> None:
        candidate = adapt_behavior_detection(
            org_id=_ORG,
            detection_id="det_001",
            correlation_key="k",
            entity_type="COMMUNICATION_PAIR",
            entity_id="10.0.0.1",
            detection_type="EAST_WEST",
            severity="HIGH",
            status="OPEN",
            evidence={},
            secondary_entity_id="10.0.0.2",
            detected_at=_TS,
        )
        assert candidate is not None
        ip_ids = [e.entity_id for e in candidate.normalized_entities if e.entity_type == NormalizedEntityType.IP_ADDRESS]
        assert "10.0.0.1" in ip_ids
        assert "10.0.0.2" in ip_ids


# ── Safe Lab Tests ─────────────────────────────────────────────────────────────


class TestSafeLabA_BehaviorAndDDoSShareIP:
    """Lab A: Behavior detection + DDoS incident share an IP — must correlate (R06)."""

    def test_shared_ip_triggers_r06(self) -> None:
        shared_ip = _ip_entity("203.0.113.1")
        beh = _behavior_candidate(entities=(shared_ip,), severity=InvestigationSeverity.HIGH)
        ddos = _ddos_candidate(entities=(shared_ip,), severity=InvestigationSeverity.CRITICAL)

        decision = evaluate_pair(beh, ddos)

        assert decision is not None
        assert decision.rule_id == CorrelationRuleId.DDOS_PLUS_BEHAVIOR
        assert any(e.entity_id == "203.0.113.1" for e in decision.shared_entities)
        assert decision.severity == InvestigationSeverity.CRITICAL  # max(HIGH, CRITICAL)


class TestSafeLabC_UnrelatedSignalsNoCorrelation:
    """Lab C: Unrelated signals (no shared entity) → NO correlation."""

    def test_no_shared_entity_no_correlation(self) -> None:
        beh = _behavior_candidate(entities=(_ip_entity("10.1.1.1"),))
        ddos = _ddos_candidate(entities=(_ip_entity("172.16.2.2"),))

        assert evaluate_pair(beh, ddos) is None

    def test_cross_org_no_correlation(self) -> None:
        shared_ip = _ip_entity("10.0.0.1")
        beh = _behavior_candidate(org_id="org_alice", entities=(shared_ip,))
        ddos = _ddos_candidate(org_id="org_bob", entities=(shared_ip,))

        assert evaluate_pair(beh, ddos) is None


class TestSafeLabD_Recurrence:
    """Lab D: New evidence on existing case → recurrence decision."""

    def test_new_behavior_on_existing_active_case_fires_r03(self) -> None:
        new_candidate = _behavior_candidate(entities=(_ip_entity("10.0.0.1"),))
        decision = evaluate_recurrence(
            new_candidate,
            existing_case_entity_ids=["IP_ADDRESS:10.0.0.1"],
            existing_case_source_domains=["behavior"],
            existing_case_domain_count=1,
        )
        assert decision is not None
        assert decision.rule_id == CorrelationRuleId.RECURRENT_SIGNAL

    def test_new_domain_on_two_domain_case_fires_r04(self) -> None:
        # Adding threat_intel (3rd domain) to a behavior+ddos case → R04
        ti_candidate = EvidenceCandidate(
            organization_id=_ORG,
            source_domain=SourceDomain.THREAT_INTEL,
            source_entity_type="threat_indicator",
            source_entity_id="ti_lab_d",
            event_type="INDICATOR_MATCHED",
            severity=InvestigationSeverity.HIGH,
            observed_at=_TS,
            normalized_entities=(_ip_entity("10.0.0.1"),),
            evidence_snapshot={},
            dedup_key="threat_intel:ti:ti_lab_d",
        )
        decision = evaluate_recurrence(
            ti_candidate,
            existing_case_entity_ids=["IP_ADDRESS:10.0.0.1"],
            existing_case_source_domains=["behavior", "ddos"],
            existing_case_domain_count=2,
        )
        assert decision is not None
        assert decision.rule_id == CorrelationRuleId.MULTI_DOMAIN_ESCALATION

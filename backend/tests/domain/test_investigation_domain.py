"""M21 Investigation domain unit tests.

Pure-function, no I/O, no database.

Covers:
  - Value object enums (StrEnum + @unique)
  - NormalizedEntity construction and str()
  - normalize_ip: IPv4, IPv6, invalid
  - normalize_resource_id: valid ULID, UUID, short/empty strings
  - normalize_detection_entity: valid, empty
  - build_correlation_key: determinism + entity order invariance
  - max_severity / max_confidence ordering
  - EvidenceCandidate construction
  - CorrelationDecision construction
  - ACTIVE_STATUS_STRINGS / ACTIVE_STATUSES / TERMINAL_STATUSES constants
  - InvestigationStatus transitions (enum value equality)
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.domain.investigations.value_objects import (
    ACTIVE_STATUS_STRINGS,
    ACTIVE_STATUSES,
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    REOPEN_WINDOW_SECONDS,
    TERMINAL_STATUSES,
    CorrelationConfidence,
    CorrelationDecision,
    CorrelationRuleId,
    EvidenceCandidate,
    EvidenceObservability,
    InvestigationSeverity,
    InvestigationStatus,
    NormalizedEntity,
    NormalizedEntityType,
    SourceDomain,
    build_correlation_key,
    max_confidence,
    max_severity,
    normalize_detection_entity,
    normalize_ip,
    normalize_resource_id,
)

# ── InvestigationStatus ────────────────────────────────────────────────────────


class TestInvestigationStatus:
    def test_string_values_are_uppercase(self) -> None:
        assert InvestigationStatus.OPEN == "OPEN"
        assert InvestigationStatus.ACKNOWLEDGED == "ACKNOWLEDGED"
        assert InvestigationStatus.INVESTIGATING == "INVESTIGATING"
        assert InvestigationStatus.RESOLVED == "RESOLVED"

    def test_is_str_subclass(self) -> None:
        assert isinstance(InvestigationStatus.OPEN, str)

    def test_active_statuses_excludes_resolved(self) -> None:
        assert InvestigationStatus.RESOLVED not in ACTIVE_STATUSES
        assert InvestigationStatus.OPEN in ACTIVE_STATUSES
        assert InvestigationStatus.ACKNOWLEDGED in ACTIVE_STATUSES
        assert InvestigationStatus.INVESTIGATING in ACTIVE_STATUSES

    def test_terminal_statuses_includes_resolved(self) -> None:
        assert InvestigationStatus.RESOLVED in TERMINAL_STATUSES
        assert InvestigationStatus.OPEN not in TERMINAL_STATUSES

    def test_active_status_strings_are_strings(self) -> None:
        for s in ACTIVE_STATUS_STRINGS:
            assert isinstance(s, str)
        assert "RESOLVED" not in ACTIVE_STATUS_STRINGS
        assert "OPEN" in ACTIVE_STATUS_STRINGS


# ── max_severity ───────────────────────────────────────────────────────────────


class TestMaxSeverity:
    def test_critical_wins_over_high(self) -> None:
        assert max_severity(InvestigationSeverity.CRITICAL, InvestigationSeverity.HIGH) == InvestigationSeverity.CRITICAL

    def test_high_wins_over_medium(self) -> None:
        assert max_severity(InvestigationSeverity.HIGH, InvestigationSeverity.MEDIUM) == InvestigationSeverity.HIGH

    def test_medium_wins_over_low(self) -> None:
        assert max_severity(InvestigationSeverity.MEDIUM, InvestigationSeverity.LOW) == InvestigationSeverity.MEDIUM

    def test_equal_severity_returns_first(self) -> None:
        assert max_severity(InvestigationSeverity.HIGH, InvestigationSeverity.HIGH) == InvestigationSeverity.HIGH

    def test_commutative(self) -> None:
        for a in InvestigationSeverity:
            for b in InvestigationSeverity:
                assert max_severity(a, b) == max_severity(b, a)


# ── max_confidence ─────────────────────────────────────────────────────────────


class TestMaxConfidence:
    def test_very_high_wins_over_high(self) -> None:
        assert max_confidence(CorrelationConfidence.VERY_HIGH, CorrelationConfidence.HIGH) == CorrelationConfidence.VERY_HIGH

    def test_high_wins_over_medium(self) -> None:
        assert max_confidence(CorrelationConfidence.HIGH, CorrelationConfidence.MEDIUM) == CorrelationConfidence.HIGH

    def test_commutative(self) -> None:
        for a in CorrelationConfidence:
            for b in CorrelationConfidence:
                assert max_confidence(a, b) == max_confidence(b, a)

    def test_equal_returns_self(self) -> None:
        assert max_confidence(CorrelationConfidence.LOW, CorrelationConfidence.LOW) == CorrelationConfidence.LOW


# ── normalize_ip ───────────────────────────────────────────────────────────────


class TestNormalizeIp:
    def test_ipv4_canonical(self) -> None:
        entity = normalize_ip("192.168.1.1")
        assert entity is not None
        assert entity.entity_type == NormalizedEntityType.IP_ADDRESS
        assert entity.entity_id == "192.168.1.1"

    def test_ipv4_with_leading_whitespace(self) -> None:
        entity = normalize_ip("  10.0.0.1  ")
        assert entity is not None
        assert entity.entity_id == "10.0.0.1"

    def test_ipv6_compressed(self) -> None:
        entity = normalize_ip("::1")
        assert entity is not None
        assert entity.entity_id == "::1"

    def test_ipv6_full_address(self) -> None:
        entity = normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert entity is not None
        # Should be compressed
        assert "0000" not in entity.entity_id

    def test_invalid_returns_none(self) -> None:
        assert normalize_ip("not-an-ip") is None
        assert normalize_ip("999.999.999.999") is None
        assert normalize_ip("") is None
        assert normalize_ip("example.com") is None

    def test_cidr_notation_invalid(self) -> None:
        # CIDR prefix is not a bare IP
        assert normalize_ip("10.0.0.0/24") is None

    def test_str_representation(self) -> None:
        entity = normalize_ip("192.168.1.1")
        assert entity is not None
        assert str(entity) == "IP_ADDRESS:192.168.1.1"


# ── normalize_resource_id ──────────────────────────────────────────────────────


class TestNormalizeResourceId:
    def test_valid_26_char_ulid(self) -> None:
        ulid = "01JTEST00000000000000000AB"
        entity = normalize_resource_id(ulid)
        assert entity is not None
        assert entity.entity_type == NormalizedEntityType.RESOURCE
        assert entity.entity_id == ulid

    def test_valid_36_char_uuid(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        entity = normalize_resource_id(uuid)
        assert entity is not None
        assert entity.entity_id == uuid

    def test_short_string_returns_none(self) -> None:
        assert normalize_resource_id("abc") is None
        assert normalize_resource_id("") is None

    def test_wrong_length_returns_none(self) -> None:
        assert normalize_resource_id("x" * 20) is None
        assert normalize_resource_id("x" * 40) is None

    def test_str_representation(self) -> None:
        ulid = "01JTEST00000000000000000AB"
        entity = normalize_resource_id(ulid)
        assert entity is not None
        assert str(entity) == f"RESOURCE:{ulid}"


# ── normalize_detection_entity ─────────────────────────────────────────────────


class TestNormalizeDetectionEntity:
    def test_valid_correlation_key(self) -> None:
        entity = normalize_detection_entity("org123|entity_type|entity_id")
        assert entity is not None
        assert entity.entity_type == NormalizedEntityType.DETECTION
        assert entity.entity_id == "org123|entity_type|entity_id"

    def test_empty_returns_none(self) -> None:
        assert normalize_detection_entity("") is None

    def test_whitespace_stripped(self) -> None:
        entity = normalize_detection_entity("  key  ")
        assert entity is not None
        assert entity.entity_id == "key"


# ── build_correlation_key ──────────────────────────────────────────────────────


class TestBuildCorrelationKey:
    def test_deterministic(self) -> None:
        key1 = build_correlation_key(
            "org_A",
            CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN,
            1,
            ["entity1", "entity2"],
        )
        key2 = build_correlation_key(
            "org_A",
            CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN,
            1,
            ["entity1", "entity2"],
        )
        assert key1 == key2

    def test_entity_order_invariant(self) -> None:
        key1 = build_correlation_key(
            "org_A",
            CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN,
            1,
            ["entity2", "entity1"],
        )
        key2 = build_correlation_key(
            "org_A",
            CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN,
            1,
            ["entity1", "entity2"],
        )
        assert key1 == key2

    def test_different_orgs_produce_different_keys(self) -> None:
        key1 = build_correlation_key("org_A", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 1, ["e1"])
        key2 = build_correlation_key("org_B", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 1, ["e1"])
        assert key1 != key2

    def test_different_rules_produce_different_keys(self) -> None:
        key1 = build_correlation_key("org_A", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 1, ["e1"])
        key2 = build_correlation_key("org_A", CorrelationRuleId.DDOS_PLUS_BEHAVIOR, 1, ["e1"])
        assert key1 != key2

    def test_different_versions_produce_different_keys(self) -> None:
        key1 = build_correlation_key("org_A", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 1, ["e1"])
        key2 = build_correlation_key("org_A", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 2, ["e1"])
        assert key1 != key2

    def test_deduplicates_entities(self) -> None:
        key1 = build_correlation_key("org_A", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 1, ["e1", "e1"])
        key2 = build_correlation_key("org_A", CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN, 1, ["e1"])
        assert key1 == key2

    def test_contains_org_and_rule(self) -> None:
        key = build_correlation_key("myorg", CorrelationRuleId.DDOS_PLUS_BEHAVIOR, 3, ["e1"])
        assert "myorg" in key
        assert "R06_DDOS_PLUS_BEHAVIOR" in key
        assert "v3" in key


# ── NormalizedEntity ───────────────────────────────────────────────────────────


class TestNormalizedEntity:
    def test_frozen(self) -> None:
        entity = NormalizedEntity(NormalizedEntityType.IP_ADDRESS, "1.2.3.4")
        with pytest.raises(AttributeError):
            entity.entity_id = "5.6.7.8"  # type: ignore[misc]

    def test_str(self) -> None:
        entity = NormalizedEntity(NormalizedEntityType.RESOURCE, "abc123")
        assert str(entity) == "RESOURCE:abc123"

    def test_equality(self) -> None:
        a = NormalizedEntity(NormalizedEntityType.IP_ADDRESS, "1.2.3.4")
        b = NormalizedEntity(NormalizedEntityType.IP_ADDRESS, "1.2.3.4")
        assert a == b

    def test_hashable(self) -> None:
        a = NormalizedEntity(NormalizedEntityType.IP_ADDRESS, "1.2.3.4")
        b = NormalizedEntity(NormalizedEntityType.IP_ADDRESS, "1.2.3.4")
        assert {a, b} == {a}


# ── EvidenceCandidate ──────────────────────────────────────────────────────────


class TestEvidenceCandidate:
    def _make(self, org_id: str = "org_A") -> EvidenceCandidate:
        ip = normalize_ip("10.0.0.1")
        assert ip is not None
        return EvidenceCandidate(
            organization_id=org_id,
            source_domain=SourceDomain.BEHAVIOR,
            source_entity_type="behavior_detection",
            source_entity_id="det_001",
            event_type="DETECTION_ACTIVE",
            severity=InvestigationSeverity.HIGH,
            observed_at=datetime(2026, 7, 1, 10, 0, 0, tzinfo=UTC),
            normalized_entities=(ip,),
            evidence_snapshot={"detection_id": "det_001"},
            dedup_key="behavior:detection:det_001",
        )

    def test_construction(self) -> None:
        c = self._make()
        assert c.organization_id == "org_A"
        assert c.source_domain == SourceDomain.BEHAVIOR
        assert len(c.normalized_entities) == 1

    def test_frozen(self) -> None:
        c = self._make()
        with pytest.raises(AttributeError):
            c.organization_id = "other"  # type: ignore[misc]

    def test_dedup_key_stable(self) -> None:
        c = self._make()
        assert c.dedup_key == "behavior:detection:det_001"


# ── CorrelationDecision ────────────────────────────────────────────────────────


class TestCorrelationDecision:
    def test_construction(self) -> None:
        ip = normalize_ip("10.0.0.1")
        assert ip is not None
        decision = CorrelationDecision(
            rule_id=CorrelationRuleId.DDOS_PLUS_BEHAVIOR,
            rule_version=1,
            shared_entities=(ip,),
            source_domains=(SourceDomain.DDOS, SourceDomain.BEHAVIOR),
            correlation_window_seconds=DEFAULT_CORRELATION_WINDOW_SECONDS,
            confidence=CorrelationConfidence.HIGH,
            severity=InvestigationSeverity.HIGH,
            reason="DDoS incident and behavior detection share entity IP_ADDRESS:10.0.0.1",
            observability=EvidenceObservability.OBSERVED,
        )
        assert decision.rule_id == CorrelationRuleId.DDOS_PLUS_BEHAVIOR
        assert decision.confidence == CorrelationConfidence.HIGH

    def test_frozen(self) -> None:
        ip = normalize_ip("10.0.0.1")
        assert ip is not None
        d = CorrelationDecision(
            rule_id=CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN,
            rule_version=1,
            shared_entities=(ip,),
            source_domains=(SourceDomain.BEHAVIOR,),
            correlation_window_seconds=3600,
            confidence=CorrelationConfidence.LOW,
            severity=InvestigationSeverity.LOW,
            reason="test",
            observability=EvidenceObservability.OBSERVED,
        )
        with pytest.raises(AttributeError):
            d.rule_id = CorrelationRuleId.DDOS_PLUS_BEHAVIOR  # type: ignore[misc]


# ── Constants ──────────────────────────────────────────────────────────────────


class TestConstants:
    def test_correlation_window_is_4_hours(self) -> None:
        assert DEFAULT_CORRELATION_WINDOW_SECONDS == 4 * 3600

    def test_reopen_window_is_24_hours(self) -> None:
        assert REOPEN_WINDOW_SECONDS == 24 * 3600

    def test_source_domain_enum_values(self) -> None:
        assert SourceDomain.BEHAVIOR == "behavior"
        assert SourceDomain.DDOS == "ddos"
        assert SourceDomain.THREAT_INTEL == "threat_intel"

    def test_correlation_rule_ids_stable(self) -> None:
        assert CorrelationRuleId.SAME_ENTITY_CROSS_DOMAIN == "R01_SAME_ENTITY_CROSS_DOMAIN"
        assert CorrelationRuleId.DDOS_PLUS_BEHAVIOR == "R06_DDOS_PLUS_BEHAVIOR"

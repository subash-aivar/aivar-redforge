from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidValidityWindowError,
)
from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
from intelligence_relationships.domain.value_objects.enums import (
    EntityType,
    EpistemicState,
    RelationshipConfidence,
    RelationshipDirection,
    RelationshipLifecycleStatus,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import (
    EvidenceCitation,
    SourceAttribution,
)
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
)
from intelligence_relationships.domain.value_objects.validity import Validity
from intelligence_relationships.domain.value_objects.version_record import VersionRecord

NOW = datetime(2026, 8, 5, tzinfo=UTC)


# ── Enums are closed and stable ──────────────────────────────────────────


def test_relationship_type_has_exactly_the_seventeen_approved_values() -> None:
    """M51.9 Phase H1 added the seven THREAT_REPORT_TO_* values below,
    closing the vocabulary gap flagged during threat_report_intel's
    certification. Every prior value is unchanged."""
    assert {t.value for t in RelationshipType} == {
        "ioc_to_malware",
        "ioc_to_tool",
        "ioc_to_infrastructure",
        "ioc_to_threat_actor",
        "ioc_to_campaign",
        "ioc_to_attack_pattern",
        "malware_to_campaign",
        "campaign_to_threat_actor",
        "tool_to_threat_actor",
        "infrastructure_to_campaign",
        "threat_report_to_threat_actor",
        "threat_report_to_campaign",
        "threat_report_to_malware",
        "threat_report_to_tool",
        "threat_report_to_infrastructure",
        "threat_report_to_attack_pattern",
        "threat_report_to_ioc",
    }


def test_entity_type_has_exactly_the_eight_approved_values() -> None:
    assert {t.value for t in EntityType} == {
        "ioc",
        "malware",
        "tool",
        "threat_actor",
        "campaign",
        "attack_pattern",
        "infrastructure",
        "threat_report",
    }


def test_epistemic_state_mirrors_the_nine_value_claim_hierarchy() -> None:
    assert [s.value for s in EpistemicState] == [
        "observation",
        "evidence",
        "hypothesis",
        "corroborated",
        "validated",
        "disputed",
        "refuted",
        "historical",
        "retired",
    ]


def test_lifecycle_status_has_the_four_approved_values() -> None:
    assert {s.value for s in RelationshipLifecycleStatus} == {
        "active",
        "deprecated",
        "revoked",
        "superseded",
    }


def test_direction_and_confidence_vocabularies() -> None:
    assert {d.value for d in RelationshipDirection} == {"unidirectional", "bidirectional"}
    assert {c.value for c in RelationshipConfidence} == {"low", "medium", "high", "very_high"}


# ── EntityRef ────────────────────────────────────────────────────────────


def test_entity_ref_rejects_empty_entity_id() -> None:
    with pytest.raises(EmptyIdentifierError):
        EntityRef(EntityType.MALWARE, "   ")


def test_entity_ref_key_is_type_qualified() -> None:
    ref = EntityRef(EntityType.CAMPAIGN, "op-aurora")
    assert ref.key == "campaign:op-aurora"
    assert str(ref) == "campaign:op-aurora"


def test_entity_refs_of_different_types_with_same_id_are_distinct() -> None:
    a = EntityRef(EntityType.MALWARE, "x")
    b = EntityRef(EntityType.TOOL, "x")
    assert a != b
    assert a.key != b.key


def test_entity_ref_is_frozen() -> None:
    ref = EntityRef(EntityType.TOOL, "cobalt-strike")
    with pytest.raises(AttributeError):
        ref.entity_id = "other"  # type: ignore[misc]


# ── EvidenceCitation ─────────────────────────────────────────────────────


def test_evidence_citation_requires_non_empty_value() -> None:
    with pytest.raises(EmptyIdentifierError):
        EvidenceCitation("")


def test_evidence_citation_str_is_its_value() -> None:
    assert str(EvidenceCitation("report-2026-08")) == "report-2026-08"


# ── SourceAttribution ────────────────────────────────────────────────────


def test_source_attribution_requires_source_system_and_reference() -> None:
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system=" ", reference="r", observed_at=NOW)
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="s", reference="", observed_at=NOW)


def test_source_attribution_confidence_defaults_to_medium() -> None:
    attribution = SourceAttribution(source_system="s", reference="r", observed_at=NOW)
    assert attribution.confidence is RelationshipConfidence.MEDIUM
    assert attribution.notes == ""


# ── Validity ─────────────────────────────────────────────────────────────


def test_validity_rejects_valid_until_at_or_before_valid_from() -> None:
    with pytest.raises(InvalidValidityWindowError):
        Validity(valid_from=NOW, valid_until=NOW)
    with pytest.raises(InvalidValidityWindowError):
        Validity(valid_from=NOW, valid_until=NOW - timedelta(days=1))


def test_open_ended_validity_covers_everything_from_valid_from() -> None:
    validity = Validity(valid_from=NOW)
    assert validity.is_open_ended()
    assert validity.covers(NOW)
    assert validity.covers(NOW + timedelta(days=3650))
    assert not validity.covers(NOW - timedelta(seconds=1))


def test_closed_validity_is_half_open() -> None:
    end = NOW + timedelta(days=10)
    validity = Validity(valid_from=NOW, valid_until=end)
    assert not validity.is_open_ended()
    assert validity.covers(NOW)
    assert validity.covers(end - timedelta(seconds=1))
    assert not validity.covers(end)


# ── VersionRecord ────────────────────────────────────────────────────────


def test_version_record_validates_its_fields() -> None:
    with pytest.raises(ValueError, match="version must be >= 1"):
        VersionRecord(version=0, changed_at=NOW, change_summary="s", source="src")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary=" ", source="src")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary="s", source="")


# ── Identifiers ──────────────────────────────────────────────────────────


def test_relationship_id_rejects_nil_uuid() -> None:
    from uuid import UUID

    with pytest.raises(ValueError, match="nil UUID"):
        IntelligenceRelationshipId(UUID(int=0))


def test_generated_relationship_ids_are_unique_and_stringify() -> None:
    a = IntelligenceRelationshipId.generate()
    b = IntelligenceRelationshipId.generate()
    assert a != b
    assert str(a) == str(a.value)

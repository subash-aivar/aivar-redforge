from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from campaign_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidCanonicalNameError,
    InvalidRegionError,
    InvalidTimelineError,
)
from campaign_intel.domain.value_objects.canonical_name import normalize_canonical_name
from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignLifecycleStatus,
    CampaignMotivation,
    CampaignObjectiveType,
    CampaignStatus,
    CampaignTargetSector,
)
from campaign_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from campaign_intel.domain.value_objects.identifiers import CampaignId
from campaign_intel.domain.value_objects.taxonomy import (
    CampaignAlias,
    CampaignObjective,
    normalize_region,
)
from campaign_intel.domain.value_objects.timeline import CampaignTimeline
from campaign_intel.domain.value_objects.version_record import VersionRecord

NOW = datetime(2026, 8, 5, tzinfo=UTC)
LATER = NOW + timedelta(days=30)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Cloud Hopper", "cloud hopper"),
        ("  CLOUD HOPPER  ", "cloud hopper"),
        ("Cloud   Hopper", "cloud hopper"),
        ("cloud_hopper", "cloud hopper"),
        ("Cloud-Hopper", "cloud hopper"),
        ("Operation\tAurora", "operation aurora"),
    ],
)
def test_normalize_canonical_name_collapses_to_one_identity(raw: str, expected: str) -> None:
    assert normalize_canonical_name(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "\t\n", "---", "___"])
def test_normalize_canonical_name_rejects_empty_result(raw: str) -> None:
    with pytest.raises(InvalidCanonicalNameError):
        normalize_canonical_name(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("eu", "EU"),
        ("  us  ", "US"),
        ("se_asia", "SE-ASIA"),
        ("se asia", "SE-ASIA"),
        ("APAC", "APAC"),
    ],
)
def test_normalize_region_is_deterministic(raw: str, expected: str) -> None:
    assert normalize_region(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "---", "EU!", "a" * 40, "*"])
def test_normalize_region_rejects_bad_format(raw: str) -> None:
    with pytest.raises(InvalidRegionError):
        normalize_region(raw)


def test_campaign_id_rejects_nil_uuid() -> None:
    with pytest.raises(ValueError, match="nil UUID"):
        CampaignId(UUID(int=0))


def test_campaign_id_generate_is_unique_and_stringifies() -> None:
    a, b = CampaignId.generate(), CampaignId.generate()
    assert a != b
    assert str(a) == str(a.value)


def test_alias_rejects_blank() -> None:
    with pytest.raises(EmptyIdentifierError):
        CampaignAlias("  ")
    assert str(CampaignAlias("APT10")) == "APT10"


def test_alias_is_frozen() -> None:
    alias = CampaignAlias("APT10")
    with pytest.raises(AttributeError):
        alias.value = "other"  # type: ignore[misc]


def test_objective_carries_closed_type_and_free_description() -> None:
    objective = CampaignObjective(
        objective_type=CampaignObjectiveType.ESPIONAGE, description="stealing IP"
    )
    assert str(objective) == "espionage"
    assert objective.description == "stealing IP"
    assert CampaignObjective(objective_type=CampaignObjectiveType.OTHER).description == ""


def test_timeline_accepts_a_valid_window() -> None:
    timeline = CampaignTimeline(first_observed=NOW, last_observed=LATER)
    assert timeline.first_observed == NOW
    assert timeline.last_observed == LATER
    assert timeline.ongoing is False


def test_timeline_rejects_reversed_window() -> None:
    with pytest.raises(InvalidTimelineError):
        CampaignTimeline(first_observed=LATER, last_observed=NOW)


def test_ongoing_timeline_must_not_carry_last_observed() -> None:
    with pytest.raises(InvalidTimelineError):
        CampaignTimeline(first_observed=NOW, last_observed=LATER, ongoing=True)
    assert CampaignTimeline(first_observed=NOW, ongoing=True).ongoing is True


def test_evidence_citation_rejects_blank() -> None:
    with pytest.raises(EmptyIdentifierError):
        EvidenceCitation("   ")
    assert str(EvidenceCitation("https://example.test/report")) == "https://example.test/report"


def test_source_attribution_requires_source_system_and_reference() -> None:
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="", reference="r", observed_at=NOW)
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="s", reference="  ", observed_at=NOW)


def test_source_attribution_defaults_to_medium_confidence() -> None:
    attribution = SourceAttribution(source_system="s", reference="r", observed_at=NOW)
    assert attribution.confidence is CampaignConfidence.MEDIUM
    assert attribution.notes == ""


def test_version_record_validation() -> None:
    with pytest.raises(ValueError, match="version must be >= 1"):
        VersionRecord(version=0, changed_at=NOW, change_summary="x", source="s")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary=" ", source="s")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary="x", source=" ")


def test_enums_are_closed_vocabularies() -> None:
    assert {s.value for s in CampaignLifecycleStatus} == {
        "active",
        "deprecated",
        "revoked",
        "superseded",
    }
    assert {s.value for s in CampaignStatus} == {
        "unknown",
        "ongoing",
        "suspected_concluded",
        "concluded",
    }
    assert {m.value for m in CampaignMotivation} == {
        "financial",
        "espionage",
        "ideological",
        "destructive",
        "unknown",
    }
    assert len(set(CampaignObjectiveType)) == 7
    assert len(set(CampaignTargetSector)) == 11
    assert {c.value for c in CampaignConfidence} == {"low", "medium", "high", "very_high"}


def test_status_and_lifecycle_status_are_disjoint_vocabularies() -> None:
    """The two axes deliberately do not share member names beyond
    nothing — a value can never be silently used for the wrong axis."""
    assert not {s.value for s in CampaignStatus} & {s.value for s in CampaignLifecycleStatus}


@pytest.mark.parametrize("bad", ["Finance", "aerospace", ""])
def test_target_sector_enum_rejects_unknown_values(bad: str) -> None:
    with pytest.raises(ValueError, match="is not a valid CampaignTargetSector"):
        CampaignTargetSector(bad)

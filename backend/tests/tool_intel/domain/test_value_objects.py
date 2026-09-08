from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from tool_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidCanonicalNameError,
)
from tool_intel.domain.value_objects.canonical_name import normalize_canonical_name
from tool_intel.domain.value_objects.enums import (
    ToolCapability,
    ToolCategory,
    ToolConfidence,
    ToolLifecycleStatus,
    ToolPlatform,
)
from tool_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from tool_intel.domain.value_objects.identifiers import ToolId
from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily
from tool_intel.domain.value_objects.version_record import VersionRecord

NOW = datetime(2026, 8, 6, tzinfo=UTC)


@pytest.mark.parametrize(
    "raw",
    ["Cobalt Strike", "  cobalt-strike ", "COBALT_STRIKE", "cobalt   strike"],
)
def test_canonical_name_collapses_to_one_identity(raw: str) -> None:
    assert normalize_canonical_name(raw) == "cobalt strike"


@pytest.mark.parametrize("raw", ["", "   ", "\t\n", "---", "___"])
def test_canonical_name_rejects_empty_forms(raw: str) -> None:
    with pytest.raises(InvalidCanonicalNameError):
        normalize_canonical_name(raw)


def test_canonical_name_rejects_non_string() -> None:
    with pytest.raises(InvalidCanonicalNameError):
        normalize_canonical_name(None)  # type: ignore[arg-type]


def test_canonical_name_applies_nfkc_normalization() -> None:
    fullwidth = "ＭＩＭＩＫＡＴＺ"  # noqa: RUF001 — fullwidth input is the point of the test
    assert normalize_canonical_name(fullwidth) == "mimikatz"


def test_tool_id_rejects_nil_uuid() -> None:
    with pytest.raises(ValueError, match="nil UUID"):
        ToolId(UUID(int=0))


def test_tool_id_generate_is_unique_and_stringifies() -> None:
    a, b = ToolId.generate(), ToolId.generate()
    assert a != b
    assert str(a) == str(a.value)


def test_tool_alias_requires_non_empty_value() -> None:
    with pytest.raises(EmptyIdentifierError):
        ToolAlias("   ")
    assert str(ToolAlias("beacon")) == "beacon"


def test_tool_family_requires_non_empty_name() -> None:
    with pytest.raises(EmptyIdentifierError):
        ToolFamily(family_name=" ")
    assert str(ToolFamily(family_name="Cobalt Strike")) == "Cobalt Strike"


def test_evidence_citation_requires_non_empty_value() -> None:
    with pytest.raises(EmptyIdentifierError):
        EvidenceCitation("")
    assert str(EvidenceCitation("https://vendor/report")) == "https://vendor/report"


def test_source_attribution_requires_source_system_and_reference() -> None:
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system=" ", reference="r", observed_at=NOW)
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="s", reference="  ", observed_at=NOW)


def test_source_attribution_defaults_to_medium_confidence() -> None:
    attribution = SourceAttribution(source_system="s", reference="r", observed_at=NOW)
    assert attribution.confidence is ToolConfidence.MEDIUM
    assert attribution.notes == ""


def test_version_record_validates_its_fields() -> None:
    with pytest.raises(ValueError, match="version must be >= 1"):
        VersionRecord(version=0, changed_at=NOW, change_summary="s", source="src")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary=" ", source="src")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary="s", source=" ")


def test_value_objects_are_frozen() -> None:
    alias = ToolAlias("x")
    with pytest.raises(AttributeError):
        alias.value = "y"  # type: ignore[misc]


def test_enum_vocabularies_are_closed_and_complete() -> None:
    assert len(ToolLifecycleStatus) == 4
    assert len(ToolCategory) == 13
    assert len(ToolPlatform) == 8
    assert len(ToolCapability) == 12
    assert len(ToolConfidence) == 4


def test_enums_reject_unknown_values() -> None:
    with pytest.raises(ValueError, match="not a valid"):
        ToolCategory("nonexistent_category")
    with pytest.raises(ValueError, match="not a valid"):
        ToolPlatform("solaris")

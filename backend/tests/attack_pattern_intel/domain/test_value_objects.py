from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidTechniqueIdError,
)
from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
from attack_pattern_intel.domain.value_objects.tactic_mapping import TacticMapping
from attack_pattern_intel.domain.value_objects.version_record import VersionRecord

NOW = datetime.now(UTC)


def test_mitre_technique_ref_valid_base() -> None:
    ref = MitreTechniqueRef("T1059")
    assert ref.effective_id == "T1059"
    assert ref.is_sub_technique is False


def test_mitre_technique_ref_valid_sub_technique() -> None:
    ref = MitreTechniqueRef("T1059", "T1059.001")
    assert ref.effective_id == "T1059.001"
    assert ref.is_sub_technique is True


@pytest.mark.parametrize("bad_id", ["1059", "TT1059", "T105", "T10599", "T1059.1", "t1059"])
def test_mitre_technique_ref_invalid_base(bad_id: str) -> None:
    with pytest.raises(InvalidTechniqueIdError):
        MitreTechniqueRef(bad_id)


def test_mitre_technique_ref_sub_technique_mismatched_prefix() -> None:
    with pytest.raises(InvalidTechniqueIdError):
        MitreTechniqueRef("T1059", "T1055.001")


def test_source_attribution_requires_non_empty_fields() -> None:
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="", reference="ref", observed_at=NOW)
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="analyst", reference="", observed_at=NOW)


def test_tactic_mapping_requires_non_empty_fields() -> None:
    with pytest.raises(EmptyIdentifierError):
        TacticMapping(tactic_id="", tactic_shortname="execution")
    with pytest.raises(EmptyIdentifierError):
        TacticMapping(tactic_id="TA0002", tactic_shortname="")


def test_version_record_requires_positive_version() -> None:
    with pytest.raises(ValueError, match="version must be >= 1"):
        VersionRecord(version=0, changed_at=NOW, change_summary="x", source="y")


def test_attack_pattern_id_rejects_nil_uuid() -> None:
    from uuid import UUID

    with pytest.raises(ValueError, match="nil UUID"):
        AttackPatternId(UUID(int=0))


def test_attack_pattern_id_generate_is_unique() -> None:
    a = AttackPatternId.generate()
    b = AttackPatternId.generate()
    assert a != b

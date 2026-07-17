"""Unit tests for the STIX → reference-data ACL mapper — M22 Phase 3
(STIX/TAXII Integration).

Pure function tests: build small, hand-crafted lists of already-parsed
STIX dataclasses (never raw JSON — that's `stix_parser`'s job, tested
separately) and assert the exact `ReferenceDataAdminService` input
DTOs `map_stix_objects` produces. No I/O, no database.
"""

from __future__ import annotations

from redforge.application.threat_intel.stix_reference_data_mapper import map_stix_objects
from redforge.domain.threat_intel.stix_objects import (
    StixAttackPattern,
    StixExternalReference,
    StixKillChainPhase,
    StixRelationship,
    StixTactic,
    StixVulnerability,
)
from redforge.domain.threat_intel.stix_value_objects import StixId

_TACTIC_STIX_ID = "x-mitre-tactic--11111111-1111-1111-1111-111111111111"
_PARENT_TECHNIQUE_STIX_ID = "attack-pattern--22222222-2222-2222-2222-222222222222"
_SUB_TECHNIQUE_STIX_ID = "attack-pattern--33333333-3333-3333-3333-333333333333"
_UNMAPPED_TECHNIQUE_STIX_ID = "attack-pattern--44444444-4444-4444-4444-444444444444"
_GROUP_STIX_ID = "intrusion-set--55555555-5555-5555-5555-555555555555"
_VULN_STIX_ID = "vulnerability--66666666-6666-6666-6666-666666666666"


def _tactic(
    *, stix_id: str = _TACTIC_STIX_ID, shortname: str = "initial-access", tactic_id: str | None = "TA0001"
) -> StixTactic:
    refs = (
        (StixExternalReference(source_name="mitre-attack", external_id=tactic_id),)
        if tactic_id
        else ()
    )
    return StixTactic(
        stix_id=StixId(stix_id),
        name="Initial Access",
        description="Getting into the network.",
        shortname=shortname,
        external_references=refs,
    )


def _technique(
    *,
    stix_id: str,
    technique_id: str | None,
    name: str = "Some Technique",
    is_sub_technique: bool = False,
    tactic_shortname: str | None = "initial-access",
    kill_chain_name: str = "mitre-attack",
) -> StixAttackPattern:
    refs = (
        (StixExternalReference(source_name="mitre-attack", external_id=technique_id),)
        if technique_id
        else ()
    )
    phases = (
        (StixKillChainPhase(kill_chain_name=kill_chain_name, phase_name=tactic_shortname),)
        if tactic_shortname
        else ()
    )
    return StixAttackPattern(
        stix_id=StixId(stix_id),
        name=name,
        description="A technique.",
        external_references=refs,
        kill_chain_phases=phases,
        is_sub_technique=is_sub_technique,
        platforms=("Windows",),
        data_sources=("Process",),
        framework_version="1.0",
    )


def _relationship(
    *, source_ref: str, target_ref: str, relationship_type: str = "uses", suffix: str = "1"
) -> StixRelationship:
    return StixRelationship(
        stix_id=StixId(f"relationship--{suffix * 8}-{suffix * 4}-{suffix * 4}-{suffix * 4}-{suffix * 12}"),
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        description="edge",
    )


def _vulnerability(*, stix_id: str = _VULN_STIX_ID, cve_id: str | None = "CVE-2024-1234") -> StixVulnerability:
    refs = (StixExternalReference(source_name="cve", external_id=cve_id),) if cve_id else ()
    return StixVulnerability(
        stix_id=StixId(stix_id), name=cve_id or "Unknown", description="A vulnerability.", external_references=refs
    )


class TestTacticMapping:
    def test_tactic_with_mitre_attack_ref_is_mapped(self) -> None:
        result = map_stix_objects([_tactic()])
        assert len(result.tactics) == 1
        assert result.tactics[0].tactic_id == "TA0001"
        assert result.tactics[0].shortname == "initial-access"
        assert result.unmapped_count == 0

    def test_tactic_without_mitre_attack_ref_is_unmapped(self) -> None:
        result = map_stix_objects([_tactic(tactic_id=None)])
        assert result.tactics == []
        assert result.unmapped_count == 1


class TestTechniqueMapping:
    def test_technique_with_ref_and_matching_tactic_resolves_tactic_ids(self) -> None:
        objects = [
            _tactic(),
            _technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id="T1001"),
        ]
        result = map_stix_objects(objects)
        assert len(result.techniques) == 1
        technique = result.techniques[0]
        assert technique.technique_id == "T1001"
        assert technique.tactic_ids == ["TA0001"]
        assert technique.is_sub_technique is False
        assert technique.parent_technique_id is None

    def test_technique_without_mitre_attack_ref_is_unmapped(self) -> None:
        result = map_stix_objects([_technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id=None)])
        assert result.techniques == []
        assert result.unmapped_count == 1

    def test_technique_tactic_reference_to_unknown_shortname_is_dropped_not_fabricated(self) -> None:
        """No tactic object is present at all — the technique's kill
        chain phase cannot resolve, so `tactic_ids` is simply empty,
        never a fabricated/guessed id."""
        result = map_stix_objects(
            [_technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id="T1001")]
        )
        assert result.techniques[0].tactic_ids == []

    def test_non_enterprise_kill_chain_is_ignored(self) -> None:
        """Only `kill_chain_name == "mitre-attack"` (Enterprise ATT&CK)
        is mapped — Mobile/ICS matrices are an out-of-scope, documented
        gap for M22."""
        objects = [
            _tactic(),
            _technique(
                stix_id=_PARENT_TECHNIQUE_STIX_ID,
                technique_id="T1001",
                kill_chain_name="mitre-mobile-attack",
            ),
        ]
        result = map_stix_objects(objects)
        assert result.techniques[0].tactic_ids == []

    def test_subtechnique_resolves_parent_via_subtechnique_of_relationship(self) -> None:
        objects = [
            _tactic(),
            _technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id="T1001"),
            _technique(
                stix_id=_SUB_TECHNIQUE_STIX_ID,
                technique_id="T1001.001",
                is_sub_technique=True,
                tactic_shortname=None,
            ),
            _relationship(
                source_ref=_SUB_TECHNIQUE_STIX_ID,
                target_ref=_PARENT_TECHNIQUE_STIX_ID,
                relationship_type="subtechnique-of",
                suffix="9",
            ),
        ]
        result = map_stix_objects(objects)
        techniques_by_id = {t.technique_id: t for t in result.techniques}
        assert techniques_by_id["T1001.001"].parent_technique_id == "T1001"
        assert techniques_by_id["T1001.001"].is_sub_technique is True

    def test_subtechnique_with_no_relationship_present_has_no_parent(self) -> None:
        result = map_stix_objects(
            [
                _technique(
                    stix_id=_SUB_TECHNIQUE_STIX_ID,
                    technique_id="T1001.001",
                    is_sub_technique=True,
                    tactic_shortname=None,
                )
            ]
        )
        assert result.techniques[0].parent_technique_id is None

    def test_subtechnique_relationship_to_an_unmapped_parent_leaves_parent_id_none(self) -> None:
        """The parent's own `attack-pattern` object never resolved a
        `technique_id` (no MITRE ATT&CK external ref) — the child must
        not fabricate a parent id it cannot verify."""
        objects = [
            _technique(
                stix_id=_SUB_TECHNIQUE_STIX_ID,
                technique_id="T1001.001",
                is_sub_technique=True,
                tactic_shortname=None,
            ),
            _technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id=None, tactic_shortname=None),
            _relationship(
                source_ref=_SUB_TECHNIQUE_STIX_ID,
                target_ref=_PARENT_TECHNIQUE_STIX_ID,
                relationship_type="subtechnique-of",
                suffix="9",
            ),
        ]
        result = map_stix_objects(objects)
        assert result.techniques[0].parent_technique_id is None


class TestRelationshipMapping:
    def test_supported_relationship_touching_a_technique_is_mapped(self) -> None:
        objects = [
            _technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id="T1001", tactic_shortname=None),
            _relationship(
                source_ref=_GROUP_STIX_ID, target_ref=_PARENT_TECHNIQUE_STIX_ID, relationship_type="uses"
            ),
        ]
        result = map_stix_objects(objects)
        assert len(result.relationships) == 1
        rel = result.relationships[0]
        assert rel.relationship_type == "uses"
        assert rel.target_technique_id == "T1001"
        assert rel.source_technique_id is None  # source_ref is a Group, not a technique

    def test_unsupported_relationship_type_is_unmapped(self) -> None:
        objects = [
            _technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id="T1001", tactic_shortname=None),
            _relationship(
                source_ref=_GROUP_STIX_ID,
                target_ref=_PARENT_TECHNIQUE_STIX_ID,
                relationship_type="attributed-to",
            ),
        ]
        result = map_stix_objects(objects)
        assert result.relationships == []
        assert result.unmapped_count == 1

    def test_relationship_touching_no_attack_pattern_is_unmapped(self) -> None:
        objects = [
            _relationship(source_ref=_GROUP_STIX_ID, target_ref=_VULN_STIX_ID, relationship_type="uses")
        ]
        result = map_stix_objects(objects)
        assert result.relationships == []
        assert result.unmapped_count == 1

    def test_relationship_referencing_an_unmapped_technique_still_included_with_null_technique_id(
        self,
    ) -> None:
        """The ref is still an `attack-pattern--...` id, so the
        relationship qualifies for inclusion, even though that
        specific attack-pattern never resolved a `technique_id`."""
        objects = [
            _technique(stix_id=_UNMAPPED_TECHNIQUE_STIX_ID, technique_id=None, tactic_shortname=None),
            _relationship(
                source_ref=_GROUP_STIX_ID,
                target_ref=_UNMAPPED_TECHNIQUE_STIX_ID,
                relationship_type="uses",
            ),
        ]
        result = map_stix_objects(objects)
        assert len(result.relationships) == 1
        assert result.relationships[0].target_technique_id is None


class TestVulnerabilityMapping:
    def test_vulnerability_with_cve_ref_is_mapped(self) -> None:
        result = map_stix_objects([_vulnerability()])
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].cve_id == "CVE-2024-1234"
        assert result.unmapped_count == 0

    def test_vulnerability_without_cve_ref_is_unmapped(self) -> None:
        result = map_stix_objects([_vulnerability(cve_id=None)])
        assert result.vulnerabilities == []
        assert result.unmapped_count == 1

    def test_vulnerability_description_is_carried_through_verbatim(self) -> None:
        vuln = _vulnerability()
        result = map_stix_objects([vuln])
        assert result.vulnerabilities[0].description == vuln.description
        # No CVSS/EPSS/KEV field is ever fabricated from STIX content.
        assert result.vulnerabilities[0].cvss_v3_score is None
        assert result.vulnerabilities[0].is_kev is False


class TestFullBatchMapping:
    def test_a_realistic_mixed_batch_maps_every_object_correctly(self) -> None:
        objects = [
            _tactic(),
            _technique(stix_id=_PARENT_TECHNIQUE_STIX_ID, technique_id="T1001"),
            _technique(
                stix_id=_SUB_TECHNIQUE_STIX_ID,
                technique_id="T1001.001",
                is_sub_technique=True,
                tactic_shortname=None,
            ),
            _relationship(
                source_ref=_SUB_TECHNIQUE_STIX_ID,
                target_ref=_PARENT_TECHNIQUE_STIX_ID,
                relationship_type="subtechnique-of",
                suffix="9",
            ),
            _relationship(
                source_ref=_GROUP_STIX_ID,
                target_ref=_PARENT_TECHNIQUE_STIX_ID,
                relationship_type="uses",
                suffix="8",
            ),
            _vulnerability(),
        ]
        result = map_stix_objects(objects)
        assert len(result.tactics) == 1
        assert len(result.techniques) == 2
        assert len(result.relationships) == 2
        assert len(result.vulnerabilities) == 1
        assert result.unmapped_count == 0

    def test_empty_batch_produces_empty_result(self) -> None:
        result = map_stix_objects([])
        assert result.tactics == []
        assert result.techniques == []
        assert result.relationships == []
        assert result.vulnerabilities == []
        assert result.unmapped_count == 0

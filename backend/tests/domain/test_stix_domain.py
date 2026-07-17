"""Domain-layer unit tests — M22 Phase 3 (STIX/TAXII Integration).

Covers the pure, I/O-free domain layer only:
  - `StixId` identifier grammar validation.
  - `stix_parser`'s five-gate container validation (byte size, JSON
    shape, object count, nesting depth) and per-object-type parsing
    (`attack-pattern`, `x-mitre-tactic`, `relationship`,
    `vulnerability`), including the Hardening Review's exact P0
    "object graph explosion" caps.

No network, no database, no application-layer collaborators.
"""

from __future__ import annotations

import json

import pytest

from redforge.domain.threat_intel.stix_exceptions import (
    InvalidStixIdError,
    MalformedStixContainerError,
    MalformedStixObjectError,
    StixContainerNestingTooDeepError,
    StixContainerTooLargeError,
    StixObjectCountExceededError,
)
from redforge.domain.threat_intel.stix_objects import (
    StixAttackPattern,
    StixRelationship,
    StixTactic,
    StixVulnerability,
)
from redforge.domain.threat_intel.stix_parser import (
    is_supported_type,
    load_stix_container,
    parse_attack_pattern,
    parse_object,
    parse_relationship,
    parse_tactic,
    parse_vulnerability,
    validate_object_list,
)
from redforge.domain.threat_intel.stix_value_objects import StixId

_TECHNIQUE_ID = "attack-pattern--f47ac10b-58cc-4372-a567-0e02b2c3d479"
_TACTIC_ID = "x-mitre-tactic--f47ac10b-58cc-4372-a567-0e02b2c3d480"
_RELATIONSHIP_ID = "relationship--f47ac10b-58cc-4372-a567-0e02b2c3d481"
_VULN_ID = "vulnerability--f47ac10b-58cc-4372-a567-0e02b2c3d482"


# ─────────────────────────────────────────────────────────────────────────────
# StixId
# ─────────────────────────────────────────────────────────────────────────────


class TestStixId:
    def test_valid_id_parses_and_exposes_stix_type(self) -> None:
        stix_id = StixId(_TECHNIQUE_ID)
        assert str(stix_id) == _TECHNIQUE_ID
        assert stix_id.stix_type == "attack-pattern"

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "not-a-stix-id",
            "attack-pattern-missing-double-dash",
            "attack-pattern--not-a-uuid",
            "AP--f47ac10b-58cc-4372-a567-0e02b2c3d479",  # type must be lowercase
        ],
    )
    def test_invalid_id_raises(self, raw: str) -> None:
        with pytest.raises(InvalidStixIdError):
            StixId(raw)

    def test_is_frozen_and_hashable(self) -> None:
        a = StixId(_TECHNIQUE_ID)
        b = StixId(_TECHNIQUE_ID)
        assert a == b
        assert hash(a) == hash(b)


# ─────────────────────────────────────────────────────────────────────────────
# load_stix_container — the five validation gates
# ─────────────────────────────────────────────────────────────────────────────


class TestLoadStixContainer:
    def test_valid_minimal_bundle_returns_objects(self) -> None:
        raw = json.dumps({"type": "bundle", "objects": [{"type": "identity", "id": "x"}]}).encode()
        objects = load_stix_container(raw)
        assert objects == [{"type": "identity", "id": "x"}]

    def test_valid_taxii_envelope_shape_is_also_accepted(self) -> None:
        """A TAXII 2.1 objects-envelope (`{"objects": [...], "more": bool}`)
        has the exact same top-level shape as a STIX bundle — this is
        deliberate, so one validator serves both."""
        raw = json.dumps({"objects": [{"type": "vulnerability", "id": _VULN_ID}], "more": False}).encode()
        objects = load_stix_container(raw)
        assert len(objects) == 1

    def test_oversized_payload_rejected_before_json_decode(self) -> None:
        import redforge.domain.threat_intel.stix_parser as stix_parser_module

        original_max = stix_parser_module.MAX_CONTAINER_BYTES
        stix_parser_module.MAX_CONTAINER_BYTES = 10
        try:
            with pytest.raises(StixContainerTooLargeError) as exc_info:
                load_stix_container(b'{"objects": []}')
            assert exc_info.value.max_bytes == 10
        finally:
            stix_parser_module.MAX_CONTAINER_BYTES = original_max

    def test_invalid_json_raises_malformed_container(self) -> None:
        with pytest.raises(MalformedStixContainerError):
            load_stix_container(b"{not valid json")

    def test_top_level_non_object_raises_malformed_container(self) -> None:
        with pytest.raises(MalformedStixContainerError):
            load_stix_container(b"[1, 2, 3]")

    def test_missing_objects_key_raises_malformed_container(self) -> None:
        with pytest.raises(MalformedStixContainerError):
            load_stix_container(b'{"type": "bundle"}')

    def test_non_array_objects_field_raises_malformed_container(self) -> None:
        with pytest.raises(MalformedStixContainerError):
            load_stix_container(b'{"objects": "not-a-list"}')

    def test_non_object_entry_in_objects_array_raises_malformed_container(self) -> None:
        with pytest.raises(MalformedStixContainerError):
            load_stix_container(b'{"objects": [1, 2, 3]}')

    def test_object_count_cap_enforced(self) -> None:
        import redforge.domain.threat_intel.stix_parser as stix_parser_module

        original_max = stix_parser_module.MAX_OBJECTS_PER_CONTAINER
        stix_parser_module.MAX_OBJECTS_PER_CONTAINER = 2
        try:
            raw = json.dumps({"objects": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}).encode()
            with pytest.raises(StixObjectCountExceededError) as exc_info:
                load_stix_container(raw)
            assert exc_info.value.count == 3
            assert exc_info.value.max_objects == 2
        finally:
            stix_parser_module.MAX_OBJECTS_PER_CONTAINER = original_max

    def test_nesting_depth_cap_enforced(self) -> None:
        import redforge.domain.threat_intel.stix_parser as stix_parser_module

        original_max = stix_parser_module.MAX_NESTING_DEPTH
        stix_parser_module.MAX_NESTING_DEPTH = 3
        try:
            # Build an object with deeply nested dicts well past the cap.
            deeply_nested: dict = {"leaf": True}
            for _ in range(10):
                deeply_nested = {"nested": deeply_nested}
            raw = json.dumps({"objects": [{"id": "a", "payload": deeply_nested}]}).encode()
            with pytest.raises(StixContainerNestingTooDeepError):
                load_stix_container(raw)
        finally:
            stix_parser_module.MAX_NESTING_DEPTH = original_max

    def test_legitimate_shallow_object_is_not_rejected_by_depth_cap(self) -> None:
        raw = json.dumps(
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": _TECHNIQUE_ID,
                        "name": "Test Technique",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1000"}
                        ],
                    }
                ]
            }
        ).encode()
        objects = load_stix_container(raw)
        assert len(objects) == 1


class TestValidateObjectList:
    """The shared gate `StixTaxiiFeedConnector` also runs against
    already-JSON-decoded TAXII envelope pages."""

    def test_accepts_a_valid_list(self) -> None:
        objects = validate_object_list([{"id": "a"}, {"id": "b"}])
        assert len(objects) == 2

    def test_rejects_a_non_dict_entry(self) -> None:
        with pytest.raises(MalformedStixContainerError):
            validate_object_list([{"id": "a"}, "not-a-dict"])

    def test_object_count_cap_enforced(self) -> None:
        import redforge.domain.threat_intel.stix_parser as stix_parser_module

        original_max = stix_parser_module.MAX_OBJECTS_PER_CONTAINER
        stix_parser_module.MAX_OBJECTS_PER_CONTAINER = 1
        try:
            with pytest.raises(StixObjectCountExceededError):
                validate_object_list([{"id": "a"}, {"id": "b"}])
        finally:
            stix_parser_module.MAX_OBJECTS_PER_CONTAINER = original_max


# ─────────────────────────────────────────────────────────────────────────────
# Per-object parsing
# ─────────────────────────────────────────────────────────────────────────────


class TestParseAttackPattern:
    def test_full_object_parses_every_field(self) -> None:
        obj = {
            "type": "attack-pattern",
            "id": _TECHNIQUE_ID,
            "name": "Phishing",
            "description": "Adversaries send phishing messages.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566", "url": "https://attack.mitre.org/techniques/T1566"}
            ],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "x_mitre_is_subtechnique": True,
            "x_mitre_deprecated": False,
            "revoked": False,
            "x_mitre_platforms": ["Windows", "macOS"],
            "x_mitre_data_sources": ["Network Traffic"],
            "x_mitre_version": "2.1",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2021-06-01T00:00:00.000Z",
        }
        parsed = parse_attack_pattern(obj)
        assert isinstance(parsed, StixAttackPattern)
        assert parsed.name == "Phishing"
        assert parsed.is_sub_technique is True
        assert parsed.platforms == ("Windows", "macOS")
        assert parsed.framework_version == "2.1"
        assert parsed.external_references[0].external_id == "T1566"
        assert parsed.kill_chain_phases[0].phase_name == "initial-access"
        assert parsed.created is not None and parsed.created.tzinfo is not None

    def test_minimal_object_uses_defaults(self) -> None:
        parsed = parse_attack_pattern({"id": _TECHNIQUE_ID, "name": "Minimal"})
        assert parsed.description == ""
        assert parsed.external_references == ()
        assert parsed.is_sub_technique is False
        assert parsed.is_deprecated is False

    def test_missing_id_raises(self) -> None:
        with pytest.raises(MalformedStixObjectError):
            parse_attack_pattern({"name": "No Id"})

    def test_missing_name_raises(self) -> None:
        with pytest.raises(MalformedStixObjectError):
            parse_attack_pattern({"id": _TECHNIQUE_ID})

    def test_invalid_id_shape_raises_invalid_stix_id_error(self) -> None:
        """`StixId.__post_init__` itself is the validation gate for id
        *shape* — `parse_attack_pattern` never re-validates that shape,
        it only requires the id to be present."""
        with pytest.raises(InvalidStixIdError):
            parse_attack_pattern({"id": "not-a-valid-stix-id", "name": "Bad Id"})


class TestParseTactic:
    def test_full_object_parses(self) -> None:
        obj = {
            "type": "x-mitre-tactic",
            "id": _TACTIC_ID,
            "name": "Initial Access",
            "description": "The adversary is trying to get into your network.",
            "x_mitre_shortname": "initial-access",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0001", "url": "https://attack.mitre.org/tactics/TA0001"}
            ],
        }
        parsed = parse_tactic(obj)
        assert isinstance(parsed, StixTactic)
        assert parsed.shortname == "initial-access"
        assert parsed.external_references[0].external_id == "TA0001"

    def test_missing_shortname_raises(self) -> None:
        with pytest.raises(MalformedStixObjectError):
            parse_tactic({"id": _TACTIC_ID, "name": "No Shortname"})


class TestParseRelationship:
    def test_full_object_parses(self) -> None:
        obj = {
            "type": "relationship",
            "id": _RELATIONSHIP_ID,
            "relationship_type": "subtechnique-of",
            "source_ref": _TECHNIQUE_ID,
            "target_ref": "attack-pattern--00000000-0000-0000-0000-000000000000",
            "description": "child of parent",
        }
        parsed = parse_relationship(obj)
        assert isinstance(parsed, StixRelationship)
        assert parsed.relationship_type == "subtechnique-of"
        assert parsed.source_ref == _TECHNIQUE_ID

    @pytest.mark.parametrize("missing_field", ["relationship_type", "source_ref", "target_ref"])
    def test_missing_required_field_raises(self, missing_field: str) -> None:
        obj = {
            "id": _RELATIONSHIP_ID,
            "relationship_type": "uses",
            "source_ref": _TECHNIQUE_ID,
            "target_ref": _TECHNIQUE_ID,
        }
        del obj[missing_field]
        with pytest.raises(MalformedStixObjectError):
            parse_relationship(obj)


class TestParseVulnerability:
    def test_full_object_parses(self) -> None:
        obj = {
            "type": "vulnerability",
            "id": _VULN_ID,
            "name": "CVE-2024-99999",
            "description": "A description of the vulnerability.",
            "external_references": [{"source_name": "cve", "external_id": "CVE-2024-99999"}],
        }
        parsed = parse_vulnerability(obj)
        assert isinstance(parsed, StixVulnerability)
        assert parsed.external_references[0].external_id == "CVE-2024-99999"

    def test_missing_name_raises(self) -> None:
        with pytest.raises(MalformedStixObjectError):
            parse_vulnerability({"id": _VULN_ID})


class TestParseObjectDispatch:
    def test_unsupported_type_returns_none_not_an_error(self) -> None:
        assert parse_object({"type": "identity", "id": "identity--x", "name": "Someone"}) is None

    def test_missing_type_returns_none(self) -> None:
        assert parse_object({"id": "no-type"}) is None

    def test_supported_type_dispatches_to_correct_parser(self) -> None:
        parsed = parse_object({"type": "vulnerability", "id": _VULN_ID, "name": "CVE-2024-1"})
        assert isinstance(parsed, StixVulnerability)

    def test_supported_type_with_missing_field_raises_not_returns_none(self) -> None:
        with pytest.raises(MalformedStixObjectError):
            parse_object({"type": "vulnerability", "id": _VULN_ID})


class TestIsSupportedType:
    @pytest.mark.parametrize(
        "stix_type", ["attack-pattern", "x-mitre-tactic", "relationship", "vulnerability"]
    )
    def test_supported_types(self, stix_type: str) -> None:
        assert is_supported_type(stix_type) is True

    @pytest.mark.parametrize("stix_type", ["identity", "malware", "intrusion-set", "campaign"])
    def test_unsupported_types(self, stix_type: str) -> None:
        assert is_supported_type(stix_type) is False

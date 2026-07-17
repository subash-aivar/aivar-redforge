"""Unit tests for the JSON-backed FrameworkDefinitionPort adapters (M24 Phase 1).

These tests exercise the real fixture files without any database or HTTP calls.
They verify that:
- Each adapter correctly declares its framework_key
- All fixture JSON is well-formed and contains required fields
- Metadata fields are present
- Requirement entries have required fields with valid domain/severity values
"""

from __future__ import annotations

import pytest

from redforge.domain.compliance.value_objects import (
    ControlDomain,
    ControlSeverity,
    FrameworkKey,
)
from redforge.infrastructure.compliance.adapters.cis import CISFrameworkAdapter
from redforge.infrastructure.compliance.adapters.hipaa import HIPAAFrameworkAdapter
from redforge.infrastructure.compliance.adapters.iso27001 import ISO27001FrameworkAdapter
from redforge.infrastructure.compliance.adapters.nist_csf import NistCsfFrameworkAdapter
from redforge.infrastructure.compliance.adapters.soc2 import SOC2FrameworkAdapter


ALL_ADAPTERS = [
    SOC2FrameworkAdapter(),
    ISO27001FrameworkAdapter(),
    NistCsfFrameworkAdapter(),
    CISFrameworkAdapter(),
    HIPAAFrameworkAdapter(),
]

EXPECTED_KEYS = {
    SOC2FrameworkAdapter: FrameworkKey.SOC2,
    ISO27001FrameworkAdapter: FrameworkKey.ISO27001,
    NistCsfFrameworkAdapter: FrameworkKey.NIST_CSF,
    CISFrameworkAdapter: FrameworkKey.CIS,
    HIPAAFrameworkAdapter: FrameworkKey.HIPAA,
}

METADATA_REQUIRED_FIELDS = [
    "name",
    "version",
    "issuing_body",
    "description",
    "effective_date",
]

REQUIREMENT_REQUIRED_FIELDS = [
    "requirement_ref",
    "title",
    "description",
    "domain",
    "severity",
    "guidance",
    "policy_threshold",
]


class TestAdapterFrameworkKeys:
    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_framework_key_matches_expected(self, adapter) -> None:
        expected = EXPECTED_KEYS[type(adapter)]
        assert adapter.framework_key == expected

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_framework_key_is_valid_enum(self, adapter) -> None:
        # Should not raise
        key = adapter.framework_key
        assert isinstance(key, FrameworkKey)


class TestAdapterMetadata:
    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_metadata_loads(self, adapter) -> None:
        meta = adapter.load_metadata()
        assert isinstance(meta, dict)

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    @pytest.mark.parametrize("field", METADATA_REQUIRED_FIELDS)
    def test_metadata_has_required_field(self, adapter, field: str) -> None:
        meta = adapter.load_metadata()
        assert field in meta, f"Missing field '{field}' in {type(adapter).__name__} metadata"

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_metadata_name_is_non_empty_string(self, adapter) -> None:
        meta = adapter.load_metadata()
        assert isinstance(meta["name"], str) and len(meta["name"]) > 0

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_metadata_effective_date_format(self, adapter) -> None:
        meta = adapter.load_metadata()
        date_str = meta["effective_date"]
        assert len(date_str) == 10 and date_str[4] == "-" and date_str[7] == "-", (
            f"effective_date '{date_str}' is not YYYY-MM-DD format"
        )


class TestAdapterRequirements:
    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_requirements_loads(self, adapter) -> None:
        reqs = adapter.load_requirements()
        assert isinstance(reqs, list)

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_requirements_non_empty(self, adapter) -> None:
        reqs = adapter.load_requirements()
        assert len(reqs) > 0, f"{type(adapter).__name__} has no requirements"

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    @pytest.mark.parametrize("field", REQUIREMENT_REQUIRED_FIELDS)
    def test_all_requirements_have_required_field(self, adapter, field: str) -> None:
        reqs = adapter.load_requirements()
        for req in reqs:
            assert field in req, (
                f"Requirement '{req.get('requirement_ref', '?')}' in "
                f"{type(adapter).__name__} is missing field '{field}'"
            )

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_requirement_refs_are_unique(self, adapter) -> None:
        reqs = adapter.load_requirements()
        refs = [r["requirement_ref"] for r in reqs]
        assert len(refs) == len(set(refs)), (
            f"{type(adapter).__name__} has duplicate requirement_refs: "
            f"{[r for r in refs if refs.count(r) > 1]}"
        )

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_all_domain_values_are_valid(self, adapter) -> None:
        valid_domains = {d.value for d in ControlDomain}
        reqs = adapter.load_requirements()
        for req in reqs:
            assert req["domain"] in valid_domains, (
                f"Requirement '{req['requirement_ref']}' in {type(adapter).__name__} "
                f"has invalid domain '{req['domain']}'"
            )

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_all_severity_values_are_valid(self, adapter) -> None:
        valid_severities = {s.value for s in ControlSeverity}
        reqs = adapter.load_requirements()
        for req in reqs:
            assert req["severity"] in valid_severities, (
                f"Requirement '{req['requirement_ref']}' in {type(adapter).__name__} "
                f"has invalid severity '{req['severity']}'"
            )

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_policy_threshold_in_range(self, adapter) -> None:
        reqs = adapter.load_requirements()
        for req in reqs:
            threshold = req.get("policy_threshold", 80)
            assert 0 <= threshold <= 100, (
                f"Requirement '{req['requirement_ref']}' in {type(adapter).__name__} "
                f"has policy_threshold={threshold} outside [0, 100]"
            )

    @pytest.mark.parametrize("adapter", ALL_ADAPTERS, ids=lambda a: type(a).__name__)
    def test_no_certified_or_compliant_strings_in_fixture(self, adapter) -> None:
        """SYSTEM INVARIANT: fixture data must never contain 'CERTIFIED' or 'COMPLIANT'."""
        reqs = adapter.load_requirements()
        for req in reqs:
            for field, value in req.items():
                if isinstance(value, str):
                    assert "CERTIFIED" not in value.upper().split(), (
                        f"Fixture contains forbidden string 'CERTIFIED' in {field}"
                    )
                    assert "COMPLIANT" not in value.upper().split(), (
                        f"Fixture contains forbidden string 'COMPLIANT' in {field}"
                    )

    def test_soc2_has_cc6_controls(self) -> None:
        adapter = SOC2FrameworkAdapter()
        reqs = adapter.load_requirements()
        refs = {r["requirement_ref"] for r in reqs}
        assert "CC6.1" in refs

    def test_iso27001_has_privileged_access_control(self) -> None:
        adapter = ISO27001FrameworkAdapter()
        reqs = adapter.load_requirements()
        refs = {r["requirement_ref"] for r in reqs}
        assert "8.2" in refs

    def test_hipaa_has_technical_safeguards(self) -> None:
        adapter = HIPAAFrameworkAdapter()
        reqs = adapter.load_requirements()
        refs = {r["requirement_ref"] for r in reqs}
        assert "164.312(a)(1)" in refs

    def test_nist_csf_has_govern_function(self) -> None:
        adapter = NistCsfFrameworkAdapter()
        reqs = adapter.load_requirements()
        refs = {r["requirement_ref"] for r in reqs}
        # NIST CSF 2.0 added GOVERN function
        govern_reqs = [r for r in reqs if r["requirement_ref"].startswith("GV.")]
        assert len(govern_reqs) >= 1

    def test_cis_has_mfa_control(self) -> None:
        adapter = CISFrameworkAdapter()
        reqs = adapter.load_requirements()
        refs = {r["requirement_ref"] for r in reqs}
        assert "CIS-6.3" in refs

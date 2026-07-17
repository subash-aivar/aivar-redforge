"""Unit tests for the Compliance domain layer (M24 Phase 1).

Tests cover:
- Value object construction and validation
- ControlRequirement creation
- FrameworkDefinition lifecycle
- ControlCatalog aggregate operations and domain event emission
- CatalogIntegrityValidator
- ControlMapping creation and lifecycle
"""

from __future__ import annotations

import pytest

from redforge.domain.compliance.entity import (
    ControlCatalog,
    ControlMapping,
    ControlRequirement,
    FrameworkDefinition,
)
from redforge.domain.compliance.events import (
    ControlMappingDefined,
    ControlMappingRevoked,
    FrameworkPublished,
    FrameworkRetired,
)
from redforge.domain.compliance.exceptions import (
    CatalogIntegrityError,
    CrossFrameworkMappingRequiredError,
    DuplicateControlMappingError,
    FrameworkAlreadyPublishedError,
    FrameworkNotFoundError,
    FrameworkRetiredError,
)
from redforge.domain.compliance.services import CatalogIntegrityValidator
from redforge.domain.compliance.value_objects import (
    ControlDomain,
    ControlMappingVersion,
    ControlSeverity,
    FrameworkKey,
    FrameworkMetadata,
    FrameworkStatus,
    MappingConfidenceHint,
    PolicyThreshold,
)
from redforge.shared.identifiers import EntityId


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _metadata(name: str = "Test Framework") -> FrameworkMetadata:
    return FrameworkMetadata(
        name=name,
        version="1.0",
        issuing_body="Test Body",
        description="A test framework.",
        effective_date="2024-01-01",
        tags=("test",),
        external_url="https://example.com",
    )


def _soc2_req(ref: str = "CC6.1") -> ControlRequirement:
    return ControlRequirement.create(
        framework_key=FrameworkKey.SOC2,
        requirement_ref=ref,
        title=f"Test control {ref}",
        description="Test description",
        domain=ControlDomain.ACCESS_CONTROL,
        severity=ControlSeverity.HIGH,
        guidance="Test guidance",
        policy_threshold=PolicyThreshold(80),
    )


def _iso_req(ref: str = "8.2") -> ControlRequirement:
    return ControlRequirement.create(
        framework_key=FrameworkKey.ISO27001,
        requirement_ref=ref,
        title=f"ISO control {ref}",
        description="ISO test description",
        domain=ControlDomain.ACCESS_CONTROL,
        severity=ControlSeverity.CRITICAL,
        guidance="ISO guidance",
        policy_threshold=PolicyThreshold(90),
    )


def _catalog_with_two_published_frameworks() -> ControlCatalog:
    catalog = ControlCatalog.create()

    # SOC 2 framework
    catalog.register_framework(FrameworkKey.SOC2, _metadata("SOC 2"))
    req_soc2 = _soc2_req("CC6.1")
    catalog.add_requirement(FrameworkKey.SOC2, req_soc2)
    catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")

    # ISO 27001 framework
    catalog.register_framework(FrameworkKey.ISO27001, _metadata("ISO 27001"))
    req_iso = _iso_req("8.2")
    catalog.add_requirement(FrameworkKey.ISO27001, req_iso)
    catalog.publish_framework(FrameworkKey.ISO27001, published_by="admin")

    # Drain events so tests start clean
    catalog.collect_events()
    return catalog


# ─── Value Object Tests ───────────────────────────────────────────────────────


class TestPolicyThreshold:
    def test_valid_range(self) -> None:
        assert PolicyThreshold(0).value == 0
        assert PolicyThreshold(100).value == 100
        assert PolicyThreshold(80).value == 80

    def test_invalid_below_zero(self) -> None:
        with pytest.raises(ValueError, match="0-100"):
            PolicyThreshold(-1)

    def test_invalid_above_100(self) -> None:
        with pytest.raises(ValueError, match="0-100"):
            PolicyThreshold(101)


class TestControlMappingVersion:
    def test_initial(self) -> None:
        v = ControlMappingVersion.initial()
        assert str(v) == "1.0"

    def test_bump_minor(self) -> None:
        v = ControlMappingVersion.initial().bump_minor()
        assert str(v) == "1.1"

    def test_invalid_major(self) -> None:
        with pytest.raises(ValueError, match="major must be"):
            ControlMappingVersion(major=0, minor=0)

    def test_invalid_minor(self) -> None:
        with pytest.raises(ValueError, match="major must be"):
            ControlMappingVersion(major=1, minor=-1)


class TestFrameworkMetadata:
    def test_from_dict(self) -> None:
        d = {
            "name": "SOC 2",
            "version": "2017",
            "issuing_body": "AICPA",
            "description": "desc",
            "effective_date": "2017-03-01",
            "tags": ["soc2"],
            "external_url": "https://aicpa.org",
        }
        meta = FrameworkMetadata.from_dict(d)
        assert meta.name == "SOC 2"
        assert meta.tags == ("soc2",)

    def test_from_dict_optional_fields_default(self) -> None:
        d = {
            "name": "F",
            "version": "1",
            "issuing_body": "B",
            "description": "d",
            "effective_date": "2020-01-01",
        }
        meta = FrameworkMetadata.from_dict(d)
        assert meta.tags == ()
        assert meta.external_url == ""


# ─── ControlRequirement Tests ─────────────────────────────────────────────────


class TestControlRequirement:
    def test_create_generates_id(self) -> None:
        req = _soc2_req()
        assert req.id is not None
        assert req.framework_key == FrameworkKey.SOC2
        assert req.requirement_ref == "CC6.1"

    def test_tags_immutable_tuple(self) -> None:
        req = ControlRequirement.create(
            framework_key=FrameworkKey.SOC2,
            requirement_ref="CC6.1",
            title="T",
            description="D",
            domain=ControlDomain.ACCESS_CONTROL,
            severity=ControlSeverity.HIGH,
            guidance="G",
            policy_threshold=PolicyThreshold(80),
            tags=("a", "b"),
        )
        assert req.tags == ("a", "b")


# ─── FrameworkDefinition Tests ────────────────────────────────────────────────


class TestFrameworkDefinition:
    def test_create_starts_as_draft(self) -> None:
        fw = FrameworkDefinition.create(FrameworkKey.SOC2, _metadata())
        assert fw.status == FrameworkStatus.DRAFT

    def test_add_requirement_increments_count(self) -> None:
        fw = FrameworkDefinition.create(FrameworkKey.SOC2, _metadata())
        fw.add_requirement(_soc2_req())
        assert fw.requirement_count() == 1

    def test_add_requirement_wrong_framework_raises(self) -> None:
        fw = FrameworkDefinition.create(FrameworkKey.SOC2, _metadata())
        iso_req = _iso_req()
        with pytest.raises(CatalogIntegrityError, match="does not match"):
            fw.add_requirement(iso_req)

    def test_add_requirement_to_retired_framework_raises(self) -> None:
        fw = FrameworkDefinition.create(FrameworkKey.SOC2, _metadata())
        fw.status = FrameworkStatus.RETIRED
        with pytest.raises(FrameworkRetiredError):
            fw.add_requirement(_soc2_req())


# ─── ControlCatalog Aggregate Tests ──────────────────────────────────────────


class TestControlCatalog:
    def test_create_empty_catalog(self) -> None:
        catalog = ControlCatalog.create()
        assert catalog.list_frameworks() == []
        assert catalog.list_active_mappings() == []

    def test_register_framework_starts_draft(self) -> None:
        catalog = ControlCatalog.create()
        fw = catalog.register_framework(FrameworkKey.SOC2, _metadata())
        assert fw.status == FrameworkStatus.DRAFT

    def test_register_duplicate_raises(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")
        catalog.collect_events()

        # Already published — cannot register again
        with pytest.raises(FrameworkAlreadyPublishedError):
            catalog.register_framework(FrameworkKey.SOC2, _metadata())

    def test_publish_framework_emits_event(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata("SOC 2"))
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        catalog.publish_framework(FrameworkKey.SOC2, published_by="admin-user")
        events = catalog.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], FrameworkPublished)
        assert events[0].framework_key == FrameworkKey.SOC2
        assert events[0].published_by == "admin-user"

    def test_publish_already_published_raises(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")
        catalog.collect_events()
        with pytest.raises(FrameworkAlreadyPublishedError):
            catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")

    def test_publish_empty_framework_raises(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        with pytest.raises(CatalogIntegrityError, match="no requirements"):
            catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")

    def test_retire_framework_emits_event(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata("SOC 2"))
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")
        catalog.collect_events()
        catalog.retire_framework(
            FrameworkKey.SOC2, reason="Superseded", retired_by="admin"
        )
        events = catalog.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], FrameworkRetired)
        assert events[0].reason == "Superseded"

    def test_retire_draft_framework_raises(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        with pytest.raises(CatalogIntegrityError, match="Only PUBLISHED"):
            catalog.retire_framework(
                FrameworkKey.SOC2, reason="Test", retired_by="admin"
            )

    def test_get_framework_not_found_raises(self) -> None:
        catalog = ControlCatalog.create()
        with pytest.raises(FrameworkNotFoundError):
            catalog.get_framework(FrameworkKey.HIPAA)

    def test_list_frameworks_status_filter(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")
        catalog.register_framework(FrameworkKey.ISO27001, _metadata())
        catalog.collect_events()

        published = catalog.list_frameworks(status=FrameworkStatus.PUBLISHED)
        drafts = catalog.list_frameworks(status=FrameworkStatus.DRAFT)
        all_fw = catalog.list_frameworks()
        assert len(published) == 1
        assert len(drafts) == 1
        assert len(all_fw) == 2

    def test_collect_events_drains_queue(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        catalog.publish_framework(FrameworkKey.SOC2, published_by="admin")
        events1 = catalog.collect_events()
        events2 = catalog.collect_events()
        assert len(events1) == 1
        assert len(events2) == 0

    def test_find_requirement(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        req_id = next(iter(soc2_fw.requirements.keys()))
        req = catalog.find_requirement(FrameworkKey.SOC2, req_id)
        assert req.framework_key == FrameworkKey.SOC2

    def test_list_requirements_domain_filter(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req("CC6.1"))
        catalog.add_requirement(
            FrameworkKey.SOC2,
            ControlRequirement.create(
                framework_key=FrameworkKey.SOC2,
                requirement_ref="CC7.1",
                title="Vulnerability Detection",
                description="D",
                domain=ControlDomain.VULNERABILITY_MANAGEMENT,
                severity=ControlSeverity.HIGH,
                guidance="G",
                policy_threshold=PolicyThreshold(80),
            ),
        )
        catalog.collect_events()

        access_reqs = catalog.list_requirements(
            FrameworkKey.SOC2, domain=ControlDomain.ACCESS_CONTROL
        )
        vuln_reqs = catalog.list_requirements(
            FrameworkKey.SOC2, domain=ControlDomain.VULNERABILITY_MANAGEMENT
        )
        assert len(access_reqs) == 1
        assert len(vuln_reqs) == 1


# ─── ControlMapping Tests ─────────────────────────────────────────────────────


class TestControlMapping:
    def test_define_mapping_cross_framework(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        iso_fw = catalog.get_framework(FrameworkKey.ISO27001)
        soc2_req = next(iter(soc2_fw.requirements.values()))
        iso_req = next(iter(iso_fw.requirements.values()))

        mapping = catalog.define_mapping(
            source_requirement_id=soc2_req.id,
            target_requirement_id=iso_req.id,
            source_framework_key=FrameworkKey.SOC2,
            target_framework_key=FrameworkKey.ISO27001,
            confidence=MappingConfidenceHint.HIGH,
            rationale="Both require MFA for privileged access",
            defined_by="admin",
        )
        assert mapping.is_active is True
        assert str(mapping.version) == "1.0"

        events = catalog.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ControlMappingDefined)
        assert events[0].confidence == MappingConfidenceHint.HIGH

    def test_define_mapping_same_framework_raises(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        reqs = list(soc2_fw.requirements.values())
        # Need two requirements in same framework
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req("CC7.1"))
        soc2_fw2 = catalog.get_framework(FrameworkKey.SOC2)
        reqs2 = list(soc2_fw2.requirements.values())
        if len(reqs2) < 2:
            pytest.skip("Not enough requirements in SOC2 for this test")
        with pytest.raises(CrossFrameworkMappingRequiredError):
            catalog.define_mapping(
                source_requirement_id=reqs2[0].id,
                target_requirement_id=reqs2[1].id,
                source_framework_key=FrameworkKey.SOC2,
                target_framework_key=FrameworkKey.SOC2,
                confidence=MappingConfidenceHint.HIGH,
                rationale="Invalid",
                defined_by="admin",
            )

    def test_define_duplicate_mapping_raises(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        iso_fw = catalog.get_framework(FrameworkKey.ISO27001)
        soc2_req = next(iter(soc2_fw.requirements.values()))
        iso_req = next(iter(iso_fw.requirements.values()))

        catalog.define_mapping(
            source_requirement_id=soc2_req.id,
            target_requirement_id=iso_req.id,
            source_framework_key=FrameworkKey.SOC2,
            target_framework_key=FrameworkKey.ISO27001,
            confidence=MappingConfidenceHint.HIGH,
            rationale="First",
            defined_by="admin",
        )
        catalog.collect_events()

        with pytest.raises(DuplicateControlMappingError):
            catalog.define_mapping(
                source_requirement_id=soc2_req.id,
                target_requirement_id=iso_req.id,
                source_framework_key=FrameworkKey.SOC2,
                target_framework_key=FrameworkKey.ISO27001,
                confidence=MappingConfidenceHint.LOW,
                rationale="Duplicate",
                defined_by="admin",
            )

    def test_revoke_mapping_emits_event(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        iso_fw = catalog.get_framework(FrameworkKey.ISO27001)
        soc2_req = next(iter(soc2_fw.requirements.values()))
        iso_req = next(iter(iso_fw.requirements.values()))

        mapping = catalog.define_mapping(
            source_requirement_id=soc2_req.id,
            target_requirement_id=iso_req.id,
            source_framework_key=FrameworkKey.SOC2,
            target_framework_key=FrameworkKey.ISO27001,
            confidence=MappingConfidenceHint.MEDIUM,
            rationale="Test",
            defined_by="admin",
        )
        catalog.collect_events()

        catalog.revoke_mapping(mapping.id, reason="No longer applicable", revoked_by="admin")
        assert mapping.is_active is False
        events = catalog.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ControlMappingRevoked)
        assert events[0].reason == "No longer applicable"

    def test_list_active_mappings_filters_revoked(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        iso_fw = catalog.get_framework(FrameworkKey.ISO27001)
        soc2_req = next(iter(soc2_fw.requirements.values()))
        iso_req = next(iter(iso_fw.requirements.values()))

        mapping = catalog.define_mapping(
            source_requirement_id=soc2_req.id,
            target_requirement_id=iso_req.id,
            source_framework_key=FrameworkKey.SOC2,
            target_framework_key=FrameworkKey.ISO27001,
            confidence=MappingConfidenceHint.HIGH,
            rationale="T",
            defined_by="admin",
        )
        catalog.collect_events()
        assert len(catalog.list_active_mappings()) == 1

        catalog.revoke_mapping(mapping.id, reason="R", revoked_by="admin")
        catalog.collect_events()
        assert len(catalog.list_active_mappings()) == 0


# ─── CatalogIntegrityValidator Tests ─────────────────────────────────────────


class TestCatalogIntegrityValidator:
    def test_validate_publishable_passes(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        catalog.add_requirement(FrameworkKey.SOC2, _soc2_req())
        validator = CatalogIntegrityValidator()
        # Should not raise
        validator.validate_publishable(catalog, FrameworkKey.SOC2)

    def test_validate_publishable_empty_raises(self) -> None:
        catalog = ControlCatalog.create()
        catalog.register_framework(FrameworkKey.SOC2, _metadata())
        validator = CatalogIntegrityValidator()
        with pytest.raises(CatalogIntegrityError, match="no requirements"):
            validator.validate_publishable(catalog, FrameworkKey.SOC2)

    def test_validate_catalog_consistency_returns_warnings(self) -> None:
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        iso_fw = catalog.get_framework(FrameworkKey.ISO27001)
        soc2_req = next(iter(soc2_fw.requirements.values()))
        iso_req = next(iter(iso_fw.requirements.values()))

        catalog.define_mapping(
            source_requirement_id=soc2_req.id,
            target_requirement_id=iso_req.id,
            source_framework_key=FrameworkKey.SOC2,
            target_framework_key=FrameworkKey.ISO27001,
            confidence=MappingConfidenceHint.HIGH,
            rationale="Valid mapping",
            defined_by="admin",
        )
        catalog.collect_events()
        validator = CatalogIntegrityValidator()
        warnings = validator.validate_catalog_consistency(catalog)
        assert warnings == []

    def test_validate_consistency_detects_orphaned_requirement(self) -> None:
        """A mapping referencing a non-existent requirement produces a warning."""
        catalog = _catalog_with_two_published_frameworks()
        soc2_fw = catalog.get_framework(FrameworkKey.SOC2)
        iso_fw = catalog.get_framework(FrameworkKey.ISO27001)
        soc2_req = next(iter(soc2_fw.requirements.values()))
        iso_req = next(iter(iso_fw.requirements.values()))

        catalog.define_mapping(
            source_requirement_id=soc2_req.id,
            target_requirement_id=iso_req.id,
            source_framework_key=FrameworkKey.SOC2,
            target_framework_key=FrameworkKey.ISO27001,
            confidence=MappingConfidenceHint.HIGH,
            rationale="T",
            defined_by="admin",
        )
        catalog.collect_events()

        # Manually corrupt the mapping to reference a non-existent requirement
        mapping = next(iter(catalog.mappings.values()))
        mapping.target_requirement_id = EntityId.generate()

        validator = CatalogIntegrityValidator()
        warnings = validator.validate_catalog_consistency(catalog)
        assert len(warnings) == 1
        assert "not found" in warnings[0]

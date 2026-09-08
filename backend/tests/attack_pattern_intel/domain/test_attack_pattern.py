from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
from attack_pattern_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
    MissingSupersededByError,
    TenantMismatchError,
)
from attack_pattern_intel.domain.factories.attack_pattern_factory import AttackPatternFactory
from attack_pattern_intel.domain.value_objects.detection_guidance import DetectionGuidance
from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus
from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId
from attack_pattern_intel.domain.value_objects.mitigation_reference import MitigationReference
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
from attack_pattern_intel.domain.value_objects.procedure_example import ProcedureExample
from attack_pattern_intel.domain.value_objects.relationship_metadata import RelationshipMetadata

NOW = datetime.now(UTC)


def _evidence(system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(source_system=system, reference="ref-1", observed_at=NOW)


def _pattern(tenant_id: TenantId | None = None) -> AttackPattern:
    factory = AttackPatternFactory()
    return factory.observe(tenant_id, MitreTechniqueRef("T1059", "T1059.001"), NOW)


def test_observe_creates_active_pattern_with_version_one() -> None:
    pattern = _pattern()
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.ACTIVE
    assert len(pattern.version_history) == 1
    assert pattern.version_history[0].version == 1
    events = pattern.pop_events()
    assert len(events) == 1
    assert type(events[0]).__name__ == "AttackPatternObserved"


def test_add_detection_guidance_appends_and_versions() -> None:
    pattern = _pattern()
    pattern.pop_events()
    guidance = DetectionGuidance(content="Look for X", attribution=_evidence())
    pattern.add_detection_guidance(None, guidance, NOW)
    assert len(pattern.detection_guidance) == 1
    assert len(pattern.version_history) == 2
    events = pattern.pop_events()
    assert type(events[0]).__name__ == "DetectionGuidanceAdded"


def test_add_mitigation_reference() -> None:
    pattern = _pattern()
    mitigation = MitigationReference(
        mitigation_id="M1038",
        name="Execution Prevention",
        description="...",
        attribution=_evidence(),
    )
    pattern.add_mitigation_reference(None, mitigation, NOW)
    assert len(pattern.mitigation_references) == 1


def test_add_procedure_example() -> None:
    pattern = _pattern()
    example = ProcedureExample(
        description="Used by APTX", attribution=_evidence(), actor_ref="APTX"
    )
    pattern.add_procedure_example(None, example, NOW)
    assert len(pattern.procedure_examples) == 1
    assert pattern.procedure_examples[0].actor_ref == "APTX"


def test_add_relationship() -> None:
    pattern = _pattern()
    target_id = AttackPatternId.generate()
    relationship = RelationshipMetadata(
        relationship_type="related-to", target_attack_pattern_id=target_id, attribution=_evidence()
    )
    pattern.add_relationship(None, relationship, NOW)
    assert len(pattern.relationship_metadata) == 1
    assert pattern.relationship_metadata[0].target_attack_pattern_id == target_id


def test_tenant_mismatch_raises() -> None:
    pattern = _pattern(tenant_id=None)
    other_tenant = TenantId.generate()
    with pytest.raises(TenantMismatchError):
        pattern.deprecate(other_tenant, _evidence(), NOW)


# ── Lifecycle transitions ───────────────────────────────────────────────────


def test_deprecate_from_active_is_legal() -> None:
    pattern = _pattern()
    pattern.deprecate(None, _evidence(), NOW)
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.DEPRECATED


def test_revoke_from_active_is_legal() -> None:
    pattern = _pattern()
    pattern.revoke(None, _evidence(), NOW)
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.REVOKED


def test_supersede_from_active_requires_target() -> None:
    pattern = _pattern()
    by = AttackPatternId.generate()
    pattern.supersede(None, by, _evidence(), NOW)
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.SUPERSEDED
    assert pattern.superseded_by == by


def test_supersede_without_target_raises() -> None:
    pattern = _pattern()
    with pytest.raises(MissingSupersededByError):
        pattern.supersede(None, None, _evidence(), NOW)  # type: ignore[arg-type]


def test_deprecated_to_active_reactivate_is_legal() -> None:
    pattern = _pattern()
    pattern.deprecate(None, _evidence(), NOW)
    pattern.reactivate(None, _evidence(), NOW)
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.ACTIVE
    assert pattern.superseded_by is None


def test_deprecated_to_revoked_is_legal() -> None:
    pattern = _pattern()
    pattern.deprecate(None, _evidence(), NOW)
    pattern.revoke(None, _evidence(), NOW)
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.REVOKED


def test_superseded_to_revoked_is_legal() -> None:
    pattern = _pattern()
    by = AttackPatternId.generate()
    pattern.supersede(None, by, _evidence(), NOW)
    pattern.revoke(None, _evidence(), NOW)
    assert pattern.lifecycle_status is TechniqueLifecycleStatus.REVOKED


@pytest.mark.parametrize(
    "setup_target",
    [
        TechniqueLifecycleStatus.REVOKED,
    ],
)
def test_revoked_is_terminal(setup_target: TechniqueLifecycleStatus) -> None:
    pattern = _pattern()
    pattern.revoke(None, _evidence(), NOW)
    with pytest.raises(InvalidLifecycleTransitionError):
        pattern.deprecate(None, _evidence(), NOW)
    with pytest.raises(InvalidLifecycleTransitionError):
        pattern.reactivate(None, _evidence(), NOW)
    with pytest.raises(InvalidLifecycleTransitionError):
        by = AttackPatternId.generate()
        pattern.supersede(None, by, _evidence(), NOW)


def test_active_cannot_reactivate() -> None:
    pattern = _pattern()
    with pytest.raises(InvalidLifecycleTransitionError):
        pattern.reactivate(None, _evidence(), NOW)


def test_superseded_cannot_deprecate_or_reactivate() -> None:
    pattern = _pattern()
    by = AttackPatternId.generate()
    pattern.supersede(None, by, _evidence(), NOW)
    with pytest.raises(InvalidLifecycleTransitionError):
        pattern.deprecate(None, _evidence(), NOW)
    with pytest.raises(InvalidLifecycleTransitionError):
        pattern.reactivate(None, _evidence(), NOW)


def test_deprecated_cannot_supersede() -> None:
    pattern = _pattern()
    pattern.deprecate(None, _evidence(), NOW)
    with pytest.raises(InvalidLifecycleTransitionError):
        by = AttackPatternId.generate()
        pattern.supersede(None, by, _evidence(), NOW)

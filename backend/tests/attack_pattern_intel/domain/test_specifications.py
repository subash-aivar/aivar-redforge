from __future__ import annotations

from datetime import UTC, datetime

from attack_pattern_intel.domain.factories.attack_pattern_factory import AttackPatternFactory
from attack_pattern_intel.domain.specifications.attack_pattern_specifications import (
    ActiveAttackPatternSpecification,
    DeprecatedOrRevokedSpecification,
    IsGlobalAttackPatternSpecification,
    IsTenantAttackPatternSpecification,
    SupersededAttackPatternSpecification,
)
from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef

NOW = datetime.now(UTC)


def _evidence() -> SourceAttribution:
    return SourceAttribution(source_system="analyst", reference="r", observed_at=NOW)


def test_active_specification() -> None:
    pattern = AttackPatternFactory().observe(None, MitreTechniqueRef("T1059"), NOW)
    assert ActiveAttackPatternSpecification().is_satisfied_by(pattern)
    assert not DeprecatedOrRevokedSpecification().is_satisfied_by(pattern)


def test_deprecated_or_revoked_specification() -> None:
    pattern = AttackPatternFactory().observe(None, MitreTechniqueRef("T1059"), NOW)
    pattern.deprecate(None, _evidence(), NOW)
    assert DeprecatedOrRevokedSpecification().is_satisfied_by(pattern)
    assert not ActiveAttackPatternSpecification().is_satisfied_by(pattern)


def test_superseded_specification() -> None:
    pattern = AttackPatternFactory().observe(None, MitreTechniqueRef("T1059"), NOW)
    pattern.supersede(None, AttackPatternId.generate(), _evidence(), NOW)
    assert SupersededAttackPatternSpecification().is_satisfied_by(pattern)


def test_global_vs_tenant_specification() -> None:
    global_pattern = AttackPatternFactory().observe(None, MitreTechniqueRef("T1059"), NOW)
    tenant_pattern = AttackPatternFactory().observe(
        TenantId.generate(), MitreTechniqueRef("T1055"), NOW
    )
    assert IsGlobalAttackPatternSpecification().is_satisfied_by(global_pattern)
    assert not IsTenantAttackPatternSpecification().is_satisfied_by(global_pattern)
    assert IsTenantAttackPatternSpecification().is_satisfied_by(tenant_pattern)
    assert not IsGlobalAttackPatternSpecification().is_satisfied_by(tenant_pattern)

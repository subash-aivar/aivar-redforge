"""Predicate specifications over `AttackPattern` (M51.3 Phase B1). Pure,
in-memory predicates only — no query building, no persistence
concerns (mirrors `ioc_intelligence.domain.specifications.
ioc_specifications`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from attack_pattern_intel.domain.value_objects.enums import TechniqueLifecycleStatus

if TYPE_CHECKING:
    from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern


class AttackPatternSpecification(Protocol):
    def is_satisfied_by(self, pattern: AttackPattern) -> bool: ...


class IsGlobalAttackPatternSpecification:
    def is_satisfied_by(self, pattern: AttackPattern) -> bool:
        return pattern.tenant_id is None


class IsTenantAttackPatternSpecification:
    def is_satisfied_by(self, pattern: AttackPattern) -> bool:
        return pattern.tenant_id is not None


class ActiveAttackPatternSpecification:
    def is_satisfied_by(self, pattern: AttackPattern) -> bool:
        return pattern.lifecycle_status is TechniqueLifecycleStatus.ACTIVE


class DeprecatedOrRevokedSpecification:
    _TERMINAL = frozenset({TechniqueLifecycleStatus.DEPRECATED, TechniqueLifecycleStatus.REVOKED})

    def is_satisfied_by(self, pattern: AttackPattern) -> bool:
        return pattern.lifecycle_status in self._TERMINAL


class SupersededAttackPatternSpecification:
    def is_satisfied_by(self, pattern: AttackPattern) -> bool:
        return pattern.lifecycle_status is TechniqueLifecycleStatus.SUPERSEDED

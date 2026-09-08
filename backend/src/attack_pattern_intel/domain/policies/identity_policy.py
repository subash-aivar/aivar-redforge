"""IdentityDedupPolicy — no duplicate (scope, technique_id,
sub_technique_id) within `attack_pattern_intel`. The domain-layer half
of the two-layer defense (see `AttackPatternApplicationService` for
the repository-existence-check half, mirroring `ioc_intelligence`'s
dedup discipline)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_pattern_intel.domain.exceptions.domain_exceptions import DuplicateAttackPatternError

if TYPE_CHECKING:
    from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
    from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef


class IdentityDedupPolicy:
    @staticmethod
    def assert_no_duplicate(
        existing: list[AttackPattern],
        mitre_technique_ref: MitreTechniqueRef,
    ) -> None:
        for pattern in existing:
            if pattern.mitre_technique_ref.effective_id == mitre_technique_ref.effective_id:
                raise DuplicateAttackPatternError(mitre_technique_ref.effective_id)

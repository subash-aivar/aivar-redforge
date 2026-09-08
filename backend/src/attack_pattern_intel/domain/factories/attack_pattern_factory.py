"""AttackPatternFactory — the single supported construction path for
`AttackPattern` aggregates (M51.3 Phase B1).

Stays pure/sync: it does NOT call the ACL port itself. Existence of
`technique_id` against the canonical `threat_intel` catalog must
already have been validated by the application service BEFORE this
factory is invoked — mirroring `ioc_intelligence`'s exact
factory-stays-pure discipline (see `IocFactory`'s docstring for the
identical split).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId

if TYPE_CHECKING:
    from datetime import datetime

    from attack_pattern_intel.domain.value_objects.data_source_ref import (
        DataComponentRef,
        DataSourceRef,
    )
    from attack_pattern_intel.domain.value_objects.identifiers import TenantId
    from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
    from attack_pattern_intel.domain.value_objects.tactic_mapping import TacticMapping


class AttackPatternFactory:
    def observe(
        self,
        tenant_id: TenantId | None,
        mitre_technique_ref: MitreTechniqueRef,
        now: datetime,
        tactic_mappings: tuple[TacticMapping, ...] = (),
        platforms: tuple[str, ...] = (),
        data_sources: tuple[DataSourceRef, ...] = (),
        data_components: tuple[DataComponentRef, ...] = (),
    ) -> AttackPattern:
        return AttackPattern.observe(
            attack_pattern_id=AttackPatternId.generate(),
            tenant_id=tenant_id,
            mitre_technique_ref=mitre_technique_ref,
            now=now,
            tactic_mappings=tactic_mappings,
            platforms=platforms,
            data_sources=data_sources,
            data_components=data_components,
        )

from __future__ import annotations

import random
from datetime import UTC, datetime
from uuid import uuid4

from attack_pattern_intel.domain.aggregates.attack_pattern import AttackPattern
from attack_pattern_intel.domain.value_objects.evidence import SourceAttribution
from attack_pattern_intel.domain.value_objects.identifiers import AttackPatternId, TenantId
from attack_pattern_intel.domain.value_objects.mitre_technique_ref import MitreTechniqueRef
from redforge.infrastructure.database.models.threat_intel_reference_data import (
    AttackTechniqueModel,
)


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def random_technique_id() -> str:
    return f"T{random.randint(1000, 1999)}"


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{random.randint(1, 10**9)}",
        observed_at=datetime(2026, 8, 5, tzinfo=UTC),
    )


def make_pattern(
    *,
    tenant_id: TenantId | None = None,
    technique_id: str | None = None,
    sub_technique_id: str | None = None,
) -> AttackPattern:
    now = datetime(2026, 8, 5, tzinfo=UTC)
    ref = MitreTechniqueRef(technique_id or random_technique_id(), sub_technique_id)
    return AttackPattern.observe(
        attack_pattern_id=AttackPatternId.generate(),
        tenant_id=tenant_id,
        mitre_technique_ref=ref,
        now=now,
    )


async def seed_attack_technique(
    session, technique_id: str, *, name: str = "Fake Technique"
) -> None:
    """Seeds a minimal row into the canonical, real `attack_techniques`
    table (M22) so ACL adapter integration tests have real data to
    query read-only against — never a second write path, this is
    purely test setup mirroring how the real reference-data loader
    would populate the table. Idempotent: a no-op if `technique_id`
    already exists (tests may share a long-lived database)."""
    from sqlalchemy import select

    existing = await session.execute(
        select(AttackTechniqueModel.id).where(AttackTechniqueModel.technique_id == technique_id)
    )
    if existing.scalar_one_or_none() is not None:
        return

    now = datetime(2026, 8, 5, tzinfo=UTC)
    row = AttackTechniqueModel(
        id=uuid4().hex[:26],
        technique_id=technique_id,
        name=name,
        description="",
        stix_id=f"attack-pattern--{uuid4()}",
        is_sub_technique="." in technique_id,
        tactic_ids=["TA0002"],
        platforms=["Windows"],
        data_sources=[],
        is_deprecated=False,
        is_revoked=False,
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    await session.flush()

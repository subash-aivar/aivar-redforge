from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import text

from intelligence_relationships.domain.aggregates.intelligence_relationship import (
    IntelligenceRelationship,
)
from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
from intelligence_relationships.domain.value_objects.enums import (
    EntityType,
    EpistemicState,
    RelationshipConfidence,
    RelationshipDirection,
    RelationshipType,
)
from intelligence_relationships.domain.value_objects.evidence import SourceAttribution
from intelligence_relationships.domain.value_objects.identifiers import (
    IntelligenceRelationshipId,
    TenantId,
)
from intelligence_relationships.domain.value_objects.validity import Validity

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

NOW = datetime(2026, 8, 5, tzinfo=UTC)


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def make_attribution(source_system: str = "redforge-analyst") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        reference=f"ref-{uuid4()}",
        observed_at=NOW,
        confidence=RelationshipConfidence.HIGH,
    )


def make_relationship(
    *,
    tenant_id: TenantId | None = None,
    relationship_type: RelationshipType = RelationshipType.MALWARE_TO_CAMPAIGN,
    source_entity: EntityRef | None = None,
    target_entity: EntityRef | None = None,
    epistemic_state: EpistemicState = EpistemicState.OBSERVATION,
) -> IntelligenceRelationship:
    return IntelligenceRelationship.observe(
        relationship_id=IntelligenceRelationshipId.generate(),
        tenant_id=tenant_id,
        relationship_type=relationship_type,
        source_entity=source_entity or EntityRef(EntityType.MALWARE, f"malware-{uuid4()}"),
        target_entity=target_entity or EntityRef(EntityType.CAMPAIGN, f"campaign-{uuid4()}"),
        direction=RelationshipDirection.UNIDIRECTIONAL,
        confidence=RelationshipConfidence.MEDIUM,
        validity=Validity(valid_from=NOW),
        now=NOW,
        epistemic_state=epistemic_state,
    )


async def seed_ioc_row(session: AsyncSession, ioc_id: UUID) -> None:
    """Insert a minimal row into `ioc_intelligence`'s real table so the
    read-only ACL adapter has genuine data to find. Test setup only —
    never a second write path in production code."""
    await session.execute(
        text(
            "INSERT INTO ioc_intelligence_iocs "
            "(id, tenant_id, ioc_type, normalized_value, lifecycle, epistemic_state, "
            " valid_from, created_at, updated_at) "
            "VALUES (:id, NULL, 'ip', :value, 'active', 'observation', "
            " :now, :now, :now)"
        ),
        {"id": ioc_id, "value": f"203.0.113.{ioc_id.int % 250}", "now": NOW},
    )
    await session.flush()


async def seed_threat_actor_row(session: AsyncSession, actor_id: UUID) -> None:
    await session.execute(
        text(
            "INSERT INTO threat_actor_intel_threat_actors "
            "(id, tenant_id, name, origin, sophistication, status, "
            " attribution_confidence, motivations, created_at, updated_at) "
            "VALUES (:id, NULL, :name, 'unknown', 'unknown', 'active', "
            " 'low', '[]', :now, :now)"
        ),
        {"id": actor_id, "name": f"actor-{actor_id}", "now": NOW},
    )
    await session.flush()


async def seed_attack_pattern_row(session: AsyncSession, pattern_id: UUID) -> None:
    await session.execute(
        text(
            "INSERT INTO attack_pattern_intel_patterns "
            "(id, tenant_id, technique_id, sub_technique_id, lifecycle_status, "
            " tactic_mappings, platforms, created_at, updated_at, row_version) "
            "VALUES (:id, NULL, :technique_id, NULL, 'active', '[]', '[]', "
            " :now, :now, 1)"
        ),
        {"id": pattern_id, "technique_id": f"T{1000 + pattern_id.int % 8999}", "now": NOW},
    )
    await session.flush()

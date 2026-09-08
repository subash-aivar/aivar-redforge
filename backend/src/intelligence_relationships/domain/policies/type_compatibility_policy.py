"""RelationshipTypeCompatibilityPolicy — the real (source, target)
entity-type pairing each `RelationshipType` requires (M51.4 Phase C1).

This mapping table is the single source of truth for what a
relationship type *means* structurally. Every value of
`RelationshipType` appears here exactly once, mapping to exactly one
ordered pair of `EntityType`s; any other pairing is rejected. There is
no wildcard and no "any" endpoint — the vocabulary is closed on both
axes by design.

    IOC_TO_MALWARE                   : IOC            -> MALWARE
    IOC_TO_TOOL                      : IOC            -> TOOL
    IOC_TO_INFRASTRUCTURE            : IOC            -> INFRASTRUCTURE
    IOC_TO_THREAT_ACTOR               : IOC            -> THREAT_ACTOR
    IOC_TO_CAMPAIGN                  : IOC            -> CAMPAIGN
    IOC_TO_ATTACK_PATTERN            : IOC            -> ATTACK_PATTERN
    MALWARE_TO_CAMPAIGN              : MALWARE        -> CAMPAIGN
    CAMPAIGN_TO_THREAT_ACTOR         : CAMPAIGN       -> THREAT_ACTOR
    TOOL_TO_THREAT_ACTOR             : TOOL           -> THREAT_ACTOR
    INFRASTRUCTURE_TO_CAMPAIGN       : INFRASTRUCTURE -> CAMPAIGN
    THREAT_REPORT_TO_THREAT_ACTOR    : THREAT_REPORT  -> THREAT_ACTOR
    THREAT_REPORT_TO_CAMPAIGN        : THREAT_REPORT  -> CAMPAIGN
    THREAT_REPORT_TO_MALWARE         : THREAT_REPORT  -> MALWARE
    THREAT_REPORT_TO_TOOL            : THREAT_REPORT  -> TOOL
    THREAT_REPORT_TO_INFRASTRUCTURE  : THREAT_REPORT  -> INFRASTRUCTURE
    THREAT_REPORT_TO_ATTACK_PATTERN  : THREAT_REPORT  -> ATTACK_PATTERN
    THREAT_REPORT_TO_IOC             : THREAT_REPORT  -> IOC

M51.9 Phase H1 added the seven `THREAT_REPORT_TO_*` rows above to close
the vocabulary gap flagged during `threat_report_intel`'s
certification: `EntityType.THREAT_REPORT` existed but no
`RelationshipType` admitted it. Every other row, every existing id,
and every existing entity-type pairing above the added rows is
unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intelligence_relationships.domain.exceptions.domain_exceptions import (
    IncompatibleRelationshipEndpointsError,
    SelfReferentialRelationshipError,
)
from intelligence_relationships.domain.value_objects.enums import EntityType, RelationshipType

if TYPE_CHECKING:
    from intelligence_relationships.domain.value_objects.entity_ref import EntityRef

_REQUIRED_ENDPOINTS: dict[RelationshipType, tuple[EntityType, EntityType]] = {
    RelationshipType.IOC_TO_MALWARE: (EntityType.IOC, EntityType.MALWARE),
    RelationshipType.IOC_TO_TOOL: (EntityType.IOC, EntityType.TOOL),
    RelationshipType.IOC_TO_INFRASTRUCTURE: (EntityType.IOC, EntityType.INFRASTRUCTURE),
    RelationshipType.IOC_TO_THREAT_ACTOR: (EntityType.IOC, EntityType.THREAT_ACTOR),
    RelationshipType.IOC_TO_CAMPAIGN: (EntityType.IOC, EntityType.CAMPAIGN),
    RelationshipType.IOC_TO_ATTACK_PATTERN: (EntityType.IOC, EntityType.ATTACK_PATTERN),
    RelationshipType.MALWARE_TO_CAMPAIGN: (EntityType.MALWARE, EntityType.CAMPAIGN),
    RelationshipType.CAMPAIGN_TO_THREAT_ACTOR: (EntityType.CAMPAIGN, EntityType.THREAT_ACTOR),
    RelationshipType.TOOL_TO_THREAT_ACTOR: (EntityType.TOOL, EntityType.THREAT_ACTOR),
    RelationshipType.INFRASTRUCTURE_TO_CAMPAIGN: (
        EntityType.INFRASTRUCTURE,
        EntityType.CAMPAIGN,
    ),
    RelationshipType.THREAT_REPORT_TO_THREAT_ACTOR: (
        EntityType.THREAT_REPORT,
        EntityType.THREAT_ACTOR,
    ),
    RelationshipType.THREAT_REPORT_TO_CAMPAIGN: (
        EntityType.THREAT_REPORT,
        EntityType.CAMPAIGN,
    ),
    RelationshipType.THREAT_REPORT_TO_MALWARE: (
        EntityType.THREAT_REPORT,
        EntityType.MALWARE,
    ),
    RelationshipType.THREAT_REPORT_TO_TOOL: (
        EntityType.THREAT_REPORT,
        EntityType.TOOL,
    ),
    RelationshipType.THREAT_REPORT_TO_INFRASTRUCTURE: (
        EntityType.THREAT_REPORT,
        EntityType.INFRASTRUCTURE,
    ),
    RelationshipType.THREAT_REPORT_TO_ATTACK_PATTERN: (
        EntityType.THREAT_REPORT,
        EntityType.ATTACK_PATTERN,
    ),
    RelationshipType.THREAT_REPORT_TO_IOC: (
        EntityType.THREAT_REPORT,
        EntityType.IOC,
    ),
}


class RelationshipTypeCompatibilityPolicy:
    @staticmethod
    def required_endpoints(
        relationship_type: RelationshipType,
    ) -> tuple[EntityType, EntityType]:
        return _REQUIRED_ENDPOINTS[relationship_type]

    @staticmethod
    def assert_compatible(
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
    ) -> None:
        expected_source, expected_target = _REQUIRED_ENDPOINTS[relationship_type]
        if (
            source_entity.entity_type is not expected_source
            or target_entity.entity_type is not expected_target
        ):
            raise IncompatibleRelationshipEndpointsError(
                relationship_type.value,
                expected_source.value,
                expected_target.value,
                source_entity.entity_type.value,
                target_entity.entity_type.value,
            )
        if source_entity.key == target_entity.key:
            raise SelfReferentialRelationshipError(source_entity.entity_id)

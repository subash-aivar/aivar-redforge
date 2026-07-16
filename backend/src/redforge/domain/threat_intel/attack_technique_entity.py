"""MITRE ATT&CK reference-data entities — M22 Phase 1.

Per the M22 Hardening Review (Part 2, DDD Validation): `AttackTactic`,
`AttackTechnique`, and `AttackTechniqueRelationship` are read-only
reference entities, not aggregates. They are globally seeded from the
public MITRE ATT&CK STIX bundle, carry no `organization_id`, and are
never mutated by tenant-facing business logic — only the (Phase 1)
admin loading path may write them, via idempotent upsert. They
therefore have identity (their natural MITRE-assigned id) but no
lifecycle state machine, no optimistic-concurrency version, and no
domain events of their own — exactly the "reference entity loaded via
a dedicated repository" shape the review calls for, matching M18's own
`results.py` immutable-record idiom for this bounded context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.threat_intel.reference_data_value_objects import (
        AttackRelationshipType,
        TacticId,
        TechniqueId,
    )


@dataclass(frozen=True, slots=True)
class AttackTactic:
    """A canonical MITRE ATT&CK tactic (e.g. `TA0001` / "Initial Access").

    Global reference data. `stix_id` is the STIX object identifier from
    the MITRE ATT&CK bundle (`x-mitre-tactic--...`), used as the
    idempotency key for re-ingestion.
    """

    tactic_id: TacticId
    name: str
    shortname: str
    description: str
    stix_id: str
    url: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """A canonical MITRE ATT&CK technique or sub-technique.

    `tactic_ids` is the (deduplicated, order-preserving) set of tactics
    this technique maps to — a technique may serve more than one tactic.
    `parent_technique_id` is set only for sub-techniques (`is_sub_technique
    is True`) and must reference an already-ingested parent technique.
    """

    technique_id: TechniqueId
    name: str
    description: str
    stix_id: str
    is_sub_technique: bool
    parent_technique_id: TechniqueId | None
    tactic_ids: tuple[TacticId, ...] = field(default_factory=tuple)
    platforms: tuple[str, ...] = field(default_factory=tuple)
    data_sources: tuple[str, ...] = field(default_factory=tuple)
    is_deprecated: bool = False
    is_revoked: bool = False
    framework_version: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AttackTechniqueRelationship:
    """A raw STIX 2.1 `relationship` object from the ATT&CK bundle,
    scoped to relationships that touch at least one technique.

    `source_ref`/`target_ref` are the raw STIX object identifiers on
    either side of the relationship — they may reference object types
    not modeled as entities in Phase 1 (Groups, Software, Mitigations).
    `source_technique_id`/`target_technique_id` are populated only when
    that side of the relationship resolves to an ingested
    `AttackTechnique`, enabling technique-to-technique traversal
    (e.g. `subtechnique-of`, `precedes`) without requiring every
    referenced STIX object type to be modeled.
    """

    stix_id: str
    relationship_type: AttackRelationshipType
    source_ref: str
    target_ref: str
    source_technique_id: TechniqueId | None
    target_technique_id: TechniqueId | None
    description: str
    created_at: datetime
    updated_at: datetime

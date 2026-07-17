"""Parsed STIX 2.1 domain objects — M22 Phase 3 (STIX/TAXII Integration).

These are the *only* STIX 2.1 object types this connector understands:
`attack-pattern` (ATT&CK technique/sub-technique), `x-mitre-tactic`
(ATT&CK tactic — a MITRE custom SDO type, not core STIX 2.1), `relationship`
(technique-to-technique and technique-to-other graph edges), and
`vulnerability` (CVE reference). Every other STIX object type present
in a real-world bundle (`identity`, `marking-definition`,
`intrusion-set`, `malware`, `tool`, `course-of-action`, `campaign`,
`report`, ...) is honestly unsupported — `stix_parser.parse_object`
returns `None` for them rather than raising, and the connector counts
them as skipped, never fabricating a mapping for object types Phase 1's
reference-data model has no entity for.

Frozen dataclasses, `slots=True` — same shape convention as every
other read-only reference-data structure in this bounded context. Raw
STIX field values are carried through largely unmodified (kill chain
phases, external references) so the ACL mapper (application layer) —
not this parsing layer — owns every RedForge-specific interpretation
decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.threat_intel.stix_value_objects import StixId


@dataclass(frozen=True, slots=True)
class StixExternalReference:
    """One entry of a STIX object's `external_references` array."""

    source_name: str
    external_id: str | None = None
    url: str | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class StixKillChainPhase:
    kill_chain_name: str
    phase_name: str


@dataclass(frozen=True, slots=True)
class StixAttackPattern:
    """A STIX 2.1 `attack-pattern` object — the SDO MITRE ATT&CK uses
    to represent one technique or sub-technique."""

    stix_id: StixId
    name: str
    description: str
    external_references: tuple[StixExternalReference, ...] = field(default_factory=tuple)
    kill_chain_phases: tuple[StixKillChainPhase, ...] = field(default_factory=tuple)
    is_sub_technique: bool = False
    is_deprecated: bool = False
    is_revoked: bool = False
    platforms: tuple[str, ...] = field(default_factory=tuple)
    data_sources: tuple[str, ...] = field(default_factory=tuple)
    framework_version: str | None = None
    created: datetime | None = None
    modified: datetime | None = None

    @property
    def stix_type(self) -> Literal["attack-pattern"]:
        return "attack-pattern"


@dataclass(frozen=True, slots=True)
class StixTactic:
    """A STIX `x-mitre-tactic` object — MITRE's custom SDO type
    representing one ATT&CK tactic. Not part of core STIX 2.1, but
    present in every MITRE ATT&CK STIX bundle/TAXII collection."""

    stix_id: StixId
    name: str
    description: str
    shortname: str
    external_references: tuple[StixExternalReference, ...] = field(default_factory=tuple)
    created: datetime | None = None
    modified: datetime | None = None

    @property
    def stix_type(self) -> Literal["x-mitre-tactic"]:
        return "x-mitre-tactic"


@dataclass(frozen=True, slots=True)
class StixRelationship:
    """A STIX 2.1 `relationship` SRO. `relationship_type` is carried
    through as the raw STIX string — mapping it to RedForge's closed
    `AttackRelationshipType` enum (and rejecting unsupported types) is
    the ACL mapper's job, not this parsing layer's."""

    stix_id: StixId
    relationship_type: str
    source_ref: str
    target_ref: str
    description: str = ""
    created: datetime | None = None
    modified: datetime | None = None

    @property
    def stix_type(self) -> Literal["relationship"]:
        return "relationship"


@dataclass(frozen=True, slots=True)
class StixVulnerability:
    """A STIX 2.1 `vulnerability` SDO. Carries only what STIX 2.1
    itself defines (name, description, external references) — CVSS/
    EPSS/CISA-KEV overlay fields are never fabricated from a STIX
    bundle; they remain `None`/`False` until a future NVD/EPSS/KEV
    sync (out of Phase 3's scope) populates them."""

    stix_id: StixId
    name: str
    description: str
    external_references: tuple[StixExternalReference, ...] = field(default_factory=tuple)
    created: datetime | None = None
    modified: datetime | None = None

    @property
    def stix_type(self) -> Literal["vulnerability"]:
        return "vulnerability"


#: Union of every STIX object type this connector can parse.
StixParsedObject = StixAttackPattern | StixTactic | StixRelationship | StixVulnerability

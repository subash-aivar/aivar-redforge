"""STIX → reference-data anti-corruption layer — M22 Phase 3
(STIX/TAXII Integration).

The exact "STIXToDomain translator class" the Hardening Review
requires before any STIX-to-domain mapping is implemented (Part 2,
Anti-Corruption Layer finding): a single, explicit, field-by-field
translation from parsed STIX 2.1 objects
(`domain.threat_intel.stix_objects`) into M22 Phase 1's reference-data
admin-service input DTOs (`TacticInput`/`TechniqueInput`/
`RelationshipInput`/`VulnerabilityInput`). Lives in the application
layer — not the domain layer — because its output type is itself an
application-layer contract (`ReferenceDataAdminService`'s own input
DTOs); the STIX *parsing* it consumes stays domain-pure
(`stix_parser.py` has zero knowledge of RedForge's reference-data
model).

Field mapping (MITRE ATT&CK Enterprise matrix only — matching the
documented, already-accepted M22 scope gap: "Full Enterprise + ICS +
Mobile matrix... Enterprise only planned"):

  `x-mitre-tactic`   -> `TacticInput`
      tactic_id  <- external_references[source_name="mitre-attack"].external_id
      shortname  <- x_mitre_shortname
      url        <- external_references[source_name="mitre-attack"].url

  `attack-pattern`   -> `TechniqueInput`
      technique_id        <- external_references[source_name="mitre-attack"].external_id
      is_sub_technique    <- x_mitre_is_subtechnique
      parent_technique_id <- resolved via a `subtechnique-of` relationship
                              (source_ref=this object, target_ref=parent)
                              whose target's own external_references
                              resolve to a technique_id
      tactic_ids          <- kill_chain_phases[kill_chain_name="mitre-attack"]
                              .phase_name, resolved against every ingested
                              tactic's x_mitre_shortname
      platforms           <- x_mitre_platforms
      data_sources        <- x_mitre_data_sources
      is_deprecated       <- x_mitre_deprecated
      is_revoked          <- revoked
      framework_version   <- x_mitre_version

  `relationship`     -> `RelationshipInput`
      Only kept when `relationship_type` is one of RedForge's closed
      `AttackRelationshipType` values AND at least one side's STIX id
      has the `attack-pattern--` prefix (mirrors
      `AttackTechniqueRelationship`'s own documented scope: "relationships
      that touch at least one technique"). Every other relationship
      (STIX confidence scores, STIX object versioning, and every
      relationship type this bounded context does not model — e.g.
      `attributed-to`, `indicates`) is honestly counted as unmapped,
      never silently dropped without a signal.

  `vulnerability`    -> `VulnerabilityInput`
      cve_id      <- external_references[source_name="cve"].external_id
      description <- description
      Every CVSS/EPSS/CISA-KEV overlay field is left at its default
      (`None`/`False`) — STIX 2.1 does not carry those, and Phase 1's
      own `Vulnerability` entity docstring is explicit that they must
      never be fabricated. They remain unset until a (future, out of
      Phase 3 scope) NVD/EPSS/CISA-KEV sync populates them.

STIX `external_references[*].url` values are stored as inert text
metadata only (`TacticInput.url`) — never fetched by this mapper or
anything downstream of it. This is the direct fix for the Hardening
Review's secondary-SSRF finding ("STIX external references contain
arbitrary URLs... must be stored as text metadata and never resolved
by the server").
"""

from __future__ import annotations

from dataclasses import dataclass, field

from redforge.application.threat_intel.reference_data_admin_service import (
    RelationshipInput,
    TacticInput,
    TechniqueInput,
    VulnerabilityInput,
)
from redforge.domain.threat_intel.reference_data_value_objects import AttackRelationshipType
from redforge.domain.threat_intel.stix_objects import (
    StixAttackPattern,
    StixExternalReference,
    StixParsedObject,
    StixRelationship,
    StixTactic,
    StixVulnerability,
)

_MITRE_ATTACK_SOURCE = "mitre-attack"
_CVE_SOURCE = "cve"
_SUBTECHNIQUE_OF = "subtechnique-of"
_ATTACK_PATTERN_PREFIX = "attack-pattern--"

_SUPPORTED_RELATIONSHIP_TYPES = frozenset(t.value for t in AttackRelationshipType)


@dataclass(slots=True)
class StixMappingResult:
    """The mapper's complete output for one batch of parsed STIX
    objects — ready to hand, list by list and in this exact order
    (tactics, then techniques, then relationships), to
    `ReferenceDataAdminService`. Order matters: techniques reference
    tactics by id and relationships reference techniques by id, and
    `ReferenceDataAdminService.upsert_techniques`/
    `upsert_technique_relationships` validate those references against
    what has *already* been ingested."""

    tactics: list[TacticInput] = field(default_factory=list)
    techniques: list[TechniqueInput] = field(default_factory=list)
    relationships: list[RelationshipInput] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityInput] = field(default_factory=list)
    #: Objects of a *supported* STIX type that could not be honestly
    #: mapped (e.g. an `attack-pattern` with no MITRE ATT&CK external
    #: reference, or a `relationship` of an unsupported type). Never
    #: silently dropped — always counted, surfaced to the caller as
    #: `FeedSyncOutcome.items_failed`.
    unmapped_count: int = 0


def _find_external_id(
    external_references: tuple[StixExternalReference, ...], source_name: str
) -> str | None:
    for ref in external_references:
        if ref.source_name == source_name and ref.external_id:
            return ref.external_id
    return None


def _find_external_url(
    external_references: tuple[StixExternalReference, ...], source_name: str
) -> str | None:
    for ref in external_references:
        if ref.source_name == source_name and ref.url:
            return ref.url
    return None


def map_stix_objects(objects: list[StixParsedObject]) -> StixMappingResult:
    """Translate one batch of already-parsed, already-validated STIX
    objects into `ReferenceDataAdminService` input DTOs. Pure function
    — no I/O, no repository access. The batch may span multiple TAXII
    pages (the connector accumulates pages before calling this once
    per sync attempt) so that a technique and the tactic/relationship
    objects that reference it can resolve against each other even if a
    TAXII server split them across pages in an inconvenient order.
    """
    tactics_raw = [o for o in objects if isinstance(o, StixTactic)]
    techniques_raw = [o for o in objects if isinstance(o, StixAttackPattern)]
    relationships_raw = [o for o in objects if isinstance(o, StixRelationship)]
    vulnerabilities_raw = [o for o in objects if isinstance(o, StixVulnerability)]

    result = StixMappingResult()

    shortname_to_tactic_id = _map_tactics(tactics_raw, result)
    stix_id_to_technique_id = _index_technique_ids(techniques_raw, result)
    _map_techniques(
        techniques_raw,
        relationships_raw,
        stix_id_to_technique_id,
        shortname_to_tactic_id,
        result,
    )
    _map_relationships(relationships_raw, stix_id_to_technique_id, result)
    _map_vulnerabilities(vulnerabilities_raw, result)
    return result


def _map_tactics(
    tactics_raw: list[StixTactic], result: StixMappingResult
) -> dict[str, str]:
    shortname_to_tactic_id: dict[str, str] = {}
    for tactic in tactics_raw:
        tactic_id = _find_external_id(tactic.external_references, _MITRE_ATTACK_SOURCE)
        if tactic_id is None:
            result.unmapped_count += 1
            continue
        shortname_to_tactic_id[tactic.shortname] = tactic_id
        result.tactics.append(
            TacticInput(
                tactic_id=tactic_id,
                name=tactic.name,
                shortname=tactic.shortname,
                stix_id=str(tactic.stix_id),
                description=tactic.description,
                url=_find_external_url(tactic.external_references, _MITRE_ATTACK_SOURCE),
            )
        )
    return shortname_to_tactic_id


def _index_technique_ids(
    techniques_raw: list[StixAttackPattern], result: StixMappingResult
) -> dict[str, str]:
    stix_id_to_technique_id: dict[str, str] = {}
    for technique in techniques_raw:
        technique_id = _find_external_id(technique.external_references, _MITRE_ATTACK_SOURCE)
        if technique_id is None:
            result.unmapped_count += 1
            continue
        stix_id_to_technique_id[str(technique.stix_id)] = technique_id
    return stix_id_to_technique_id


def _map_techniques(
    techniques_raw: list[StixAttackPattern],
    relationships_raw: list[StixRelationship],
    stix_id_to_technique_id: dict[str, str],
    shortname_to_tactic_id: dict[str, str],
    result: StixMappingResult,
) -> None:
    child_to_parent_stix_id = {
        rel.source_ref: rel.target_ref
        for rel in relationships_raw
        if rel.relationship_type == _SUBTECHNIQUE_OF
    }

    for technique in techniques_raw:
        technique_id = stix_id_to_technique_id.get(str(technique.stix_id))
        if technique_id is None:
            continue  # already counted as unmapped by `_index_technique_ids`

        parent_technique_id: str | None = None
        if technique.is_sub_technique:
            parent_stix_id = child_to_parent_stix_id.get(str(technique.stix_id))
            if parent_stix_id is not None:
                parent_technique_id = stix_id_to_technique_id.get(parent_stix_id)

        tactic_ids: list[str] = []
        for phase in technique.kill_chain_phases:
            if phase.kill_chain_name != _MITRE_ATTACK_SOURCE:
                continue
            resolved = shortname_to_tactic_id.get(phase.phase_name)
            if resolved is not None and resolved not in tactic_ids:
                tactic_ids.append(resolved)

        result.techniques.append(
            TechniqueInput(
                technique_id=technique_id,
                name=technique.name,
                stix_id=str(technique.stix_id),
                description=technique.description,
                is_sub_technique=technique.is_sub_technique,
                parent_technique_id=parent_technique_id,
                tactic_ids=tactic_ids,
                platforms=list(technique.platforms),
                data_sources=list(technique.data_sources),
                is_deprecated=technique.is_deprecated,
                is_revoked=technique.is_revoked,
                framework_version=technique.framework_version,
            )
        )


def _map_relationships(
    relationships_raw: list[StixRelationship],
    stix_id_to_technique_id: dict[str, str],
    result: StixMappingResult,
) -> None:
    for rel in relationships_raw:
        if rel.relationship_type not in _SUPPORTED_RELATIONSHIP_TYPES:
            result.unmapped_count += 1
            continue
        touches_technique = rel.source_ref.startswith(
            _ATTACK_PATTERN_PREFIX
        ) or rel.target_ref.startswith(_ATTACK_PATTERN_PREFIX)
        if not touches_technique:
            result.unmapped_count += 1
            continue
        result.relationships.append(
            RelationshipInput(
                stix_id=str(rel.stix_id),
                relationship_type=rel.relationship_type,
                source_ref=rel.source_ref,
                target_ref=rel.target_ref,
                source_technique_id=stix_id_to_technique_id.get(rel.source_ref),
                target_technique_id=stix_id_to_technique_id.get(rel.target_ref),
                description=rel.description,
            )
        )


def _map_vulnerabilities(
    vulnerabilities_raw: list[StixVulnerability], result: StixMappingResult
) -> None:
    for vuln in vulnerabilities_raw:
        cve_id = _find_external_id(vuln.external_references, _CVE_SOURCE)
        if cve_id is None:
            result.unmapped_count += 1
            continue
        result.vulnerabilities.append(
            VulnerabilityInput(cve_id=cve_id, description=vuln.description)
        )

"""STIX 2.1 parsing and validation — M22 Phase 3 (STIX/TAXII Integration).

Deliberately does NOT use the third-party `stix2` Python library. The
Hardening Review (Part 1, "Malicious STIX bundle can trigger object
graph explosion during parsing") documents that `stix2.Bundle.parse()`
builds an in-memory, fully cross-referenced object graph and does not
itself bound memory usage against a crafted, deeply-nested or
massively-relational bundle. Rather than depend on a third-party
library's internal graph-resolution behavior (and take on its own
supply-chain surface for a use case that only needs four specific,
narrow SDO shapes), this module hand-parses exactly the fields Phase 3
maps and nothing else — every object is a flat, independent dict read,
never resolved against other objects during parsing. Cross-object
relationships (e.g. resolving a sub-technique's parent) are the ACL
mapper's job, operating on the small, already-capped, already-typed
list this module returns.

Every entry point here is a pure function: raw `bytes` (or an
already-decoded `dict`) in, typed domain objects out. No I/O.

Validation order, matching the Hardening Review's exact required
sequence (Part 8, item 5 — "Add pre-validation gate for STIX bundle
ingestion... at the raw bytes/JSON level, before parsing"):

  1. Raw byte-length cap (`MAX_CONTAINER_BYTES`) — before `json.loads`.
  2. JSON decode (a `RecursionError` from a maliciously deep payload is
     caught and reclassified, never left to crash the caller).
  3. Container shape check — must be a dict with an `objects` list
     (this is deliberately true of BOTH a STIX 2.1 `bundle` object
     — `{"type": "bundle", "objects": [...]}` — and a TAXII 2.1
     objects-endpoint Envelope — `{"objects": [...], "more": bool}`
     — so one validator serves both "STIX bundle validation" and
     "TAXII envelope validation").
  4. Object-count cap (`MAX_OBJECTS_PER_CONTAINER`) on `len(objects)`.
  5. Nesting-depth cap (`MAX_NESTING_DEPTH`), walked iteratively with
     an explicit stack (never Python recursion) and an early exit the
     moment the cap is exceeded, so an attacker cannot make this check
     itself expensive.

Only after all five gates pass does any individual object get parsed
into a typed dataclass.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.stix_exceptions import (
    MalformedStixContainerError,
    MalformedStixObjectError,
    StixContainerNestingTooDeepError,
    StixContainerTooLargeError,
    StixObjectCountExceededError,
)
from redforge.domain.threat_intel.stix_objects import (
    StixAttackPattern,
    StixExternalReference,
    StixKillChainPhase,
    StixParsedObject,
    StixRelationship,
    StixTactic,
    StixVulnerability,
)
from redforge.domain.threat_intel.stix_value_objects import StixId

if TYPE_CHECKING:
    from collections.abc import Callable

#: A full MITRE ATT&CK Enterprise STIX bundle is ~15-20MB; a single
#: TAXII collection page is expected to be far smaller (server-side
#: pagination). 24MB is generous headroom for either shape while still
#: being a hard, enforced bound — not "however large the feed feels
#: like sending today".
MAX_CONTAINER_BYTES = 24 * 1024 * 1024

#: Defense in depth against a server ignoring the page `limit` this
#: connector requests (see `taxii_client.DEFAULT_PAGE_LIMIT`). The
#: current MITRE ATT&CK Enterprise bundle holds ~700 techniques + ~14
#: tactics + thousands of relationships — comfortably under this cap
#: even as one single (non-paginated) container.
MAX_OBJECTS_PER_CONTAINER = 10_000

#: STIX objects are shallow by construction (a handful of scalar
#: fields plus small arrays of small objects like
#: `external_references`/`kill_chain_phases`). 20 is generous headroom
#: for any legitimate object while still rejecting a crafted,
#: pathologically nested payload.
MAX_NESTING_DEPTH = 20

_SUPPORTED_TYPES = frozenset({"attack-pattern", "x-mitre-tactic", "relationship", "vulnerability"})


def _parse_timestamp(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _check_nesting_depth(value: Any, *, max_depth: int) -> None:
    """Iterative (non-recursive) depth walk with an early exit the
    instant `max_depth` is exceeded — bounded cost regardless of how
    the attacker shaped the payload."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise StixContainerNestingTooDeepError(max_depth)
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)


def validate_object_list(objects: list[Any]) -> list[dict[str, Any]]:
    """Apply the object-count and nesting-depth caps to an *already
    JSON-decoded* `objects` array — the shared validation gate used by
    both `load_stix_container` (a raw STIX bundle byte payload) and
    `StixTaxiiFeedConnector` (a TAXII `/objects/` page, which
    `TaxiiClient` has already JSON-decoded and size-capped at the HTTP
    layer, but never object-count- or nesting-depth-checked). This is
    what makes "STIX bundle validation" and "TAXII envelope
    validation" the exact same enforced gate rather than two
    independently-maintained implementations.
    """
    if len(objects) > MAX_OBJECTS_PER_CONTAINER:
        raise StixObjectCountExceededError(len(objects), MAX_OBJECTS_PER_CONTAINER)

    _check_nesting_depth(objects, max_depth=MAX_NESTING_DEPTH)

    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            raise MalformedStixContainerError(f"objects[{index}] is not a JSON object")

    return objects


def load_stix_container(raw: bytes) -> list[dict[str, Any]]:
    """Validate a raw STIX bundle / TAXII objects-envelope payload and
    return its `objects` array as plain dicts, ready for
    `parse_object`. Raises a `stix_exceptions.ValidationError` subclass
    on any violation; never returns a partially-validated result.
    """
    if len(raw) > MAX_CONTAINER_BYTES:
        raise StixContainerTooLargeError(len(raw), MAX_CONTAINER_BYTES)

    try:
        container = json.loads(raw)
    except RecursionError as exc:
        raise StixContainerNestingTooDeepError(MAX_NESTING_DEPTH) from exc
    except json.JSONDecodeError as exc:
        raise MalformedStixContainerError(f"invalid JSON: {exc}") from exc

    if not isinstance(container, dict):
        raise MalformedStixContainerError("top-level JSON value must be an object")

    objects = container.get("objects")
    if not isinstance(objects, list):
        raise MalformedStixContainerError("missing or non-array 'objects' field")

    return validate_object_list(objects)


def _parse_external_references(raw: Any) -> tuple[StixExternalReference, ...]:
    if not isinstance(raw, list):
        return ()
    refs: list[StixExternalReference] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        source_name = entry.get("source_name")
        if not isinstance(source_name, str) or not source_name:
            continue
        refs.append(
            StixExternalReference(
                source_name=source_name,
                external_id=entry.get("external_id"),
                url=entry.get("url"),
                description=entry.get("description"),
            )
        )
    return tuple(refs)


def _parse_kill_chain_phases(raw: Any) -> tuple[StixKillChainPhase, ...]:
    if not isinstance(raw, list):
        return ()
    phases: list[StixKillChainPhase] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name, phase = entry.get("kill_chain_name"), entry.get("phase_name")
        if isinstance(name, str) and isinstance(phase, str) and name and phase:
            phases.append(StixKillChainPhase(kill_chain_name=name, phase_name=phase))
    return tuple(phases)


def _require_str(obj: dict[str, Any], field_name: str, stix_id_for_error: str) -> str:
    value = obj.get(field_name)
    if not isinstance(value, str) or not value:
        raise MalformedStixObjectError(stix_id_for_error, f"missing or empty '{field_name}'")
    return value


def parse_attack_pattern(obj: dict[str, Any]) -> StixAttackPattern:
    raw_id = obj.get("id", "")
    stix_id = StixId(raw_id) if raw_id else None
    if stix_id is None:
        raise MalformedStixObjectError(str(raw_id), "missing 'id'")
    name = _require_str(obj, "name", str(stix_id))
    return StixAttackPattern(
        stix_id=stix_id,
        name=name,
        description=obj.get("description") or "",
        external_references=_parse_external_references(obj.get("external_references")),
        kill_chain_phases=_parse_kill_chain_phases(obj.get("kill_chain_phases")),
        is_sub_technique=bool(obj.get("x_mitre_is_subtechnique", False)),
        is_deprecated=bool(obj.get("x_mitre_deprecated", False)),
        is_revoked=bool(obj.get("revoked", False)),
        platforms=tuple(p for p in obj.get("x_mitre_platforms") or () if isinstance(p, str)),
        data_sources=tuple(
            d for d in obj.get("x_mitre_data_sources") or () if isinstance(d, str)
        ),
        framework_version=(
            str(obj["x_mitre_version"]) if obj.get("x_mitre_version") is not None else None
        ),
        created=_parse_timestamp(obj.get("created")),
        modified=_parse_timestamp(obj.get("modified")),
    )


def parse_tactic(obj: dict[str, Any]) -> StixTactic:
    raw_id = obj.get("id", "")
    stix_id = StixId(raw_id) if raw_id else None
    if stix_id is None:
        raise MalformedStixObjectError(str(raw_id), "missing 'id'")
    name = _require_str(obj, "name", str(stix_id))
    shortname = _require_str(obj, "x_mitre_shortname", str(stix_id))
    return StixTactic(
        stix_id=stix_id,
        name=name,
        description=obj.get("description") or "",
        shortname=shortname,
        external_references=_parse_external_references(obj.get("external_references")),
        created=_parse_timestamp(obj.get("created")),
        modified=_parse_timestamp(obj.get("modified")),
    )


def parse_relationship(obj: dict[str, Any]) -> StixRelationship:
    raw_id = obj.get("id", "")
    stix_id = StixId(raw_id) if raw_id else None
    if stix_id is None:
        raise MalformedStixObjectError(str(raw_id), "missing 'id'")
    relationship_type = _require_str(obj, "relationship_type", str(stix_id))
    source_ref = _require_str(obj, "source_ref", str(stix_id))
    target_ref = _require_str(obj, "target_ref", str(stix_id))
    return StixRelationship(
        stix_id=stix_id,
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        description=obj.get("description") or "",
        created=_parse_timestamp(obj.get("created")),
        modified=_parse_timestamp(obj.get("modified")),
    )


def parse_vulnerability(obj: dict[str, Any]) -> StixVulnerability:
    raw_id = obj.get("id", "")
    stix_id = StixId(raw_id) if raw_id else None
    if stix_id is None:
        raise MalformedStixObjectError(str(raw_id), "missing 'id'")
    name = _require_str(obj, "name", str(stix_id))
    return StixVulnerability(
        stix_id=stix_id,
        name=name,
        description=obj.get("description") or "",
        external_references=_parse_external_references(obj.get("external_references")),
        created=_parse_timestamp(obj.get("created")),
        modified=_parse_timestamp(obj.get("modified")),
    )


_PARSERS: dict[str, Callable[[dict[str, Any]], StixParsedObject]] = {
    "attack-pattern": parse_attack_pattern,
    "x-mitre-tactic": parse_tactic,
    "relationship": parse_relationship,
    "vulnerability": parse_vulnerability,
}


def parse_object(obj: dict[str, Any]) -> StixParsedObject | None:
    """Parse one raw STIX object dict into its typed dataclass.

    Returns `None` (never raises) for any `type` outside the four
    supported SDOs/SROs — an unsupported type is not a malformed
    object, it is simply not one Phase 3 maps into anything. Raises
    `MalformedStixObjectError` only when the object's `type` IS one of
    the four supported kinds but is missing a required field.
    """
    stix_type = obj.get("type")
    parser = _PARSERS.get(stix_type) if isinstance(stix_type, str) else None
    if parser is None:
        return None
    return parser(obj)


def is_supported_type(stix_type: str) -> bool:
    return stix_type in _SUPPORTED_TYPES

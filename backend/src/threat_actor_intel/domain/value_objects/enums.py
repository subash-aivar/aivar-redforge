"""Closed enums for threat_actor_intel (M51A)."""

from __future__ import annotations

from enum import StrEnum


class ThreatActorOrigin(StrEnum):
    """The broad category of actor, independent of any specific
    campaign or operation — a stable classification used to filter
    and prioritize which actors matter to a given tenant."""

    NATION_STATE = "nation_state"
    CRIMINAL = "criminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    UNKNOWN = "unknown"


class MotivationType(StrEnum):
    """An actor may hold more than one motivation simultaneously
    (e.g. a nation-state actor pursuing both espionage and
    destruction) — modeled as a `frozenset[MotivationType]` on the
    aggregate rather than a single value."""

    ESPIONAGE = "espionage"
    FINANCIAL = "financial"
    IDEOLOGICAL = "ideological"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class SophisticationLevel(StrEnum):
    """A coarse capability tier, ordered from least to most capable.
    Mirrors the shape of MITRE ATT&CK's own actor-sophistication
    vocabulary without importing or depending on
    `redforge.domain.threat_intel`'s ATT&CK modeling."""

    NOVICE = "novice"
    PRACTITIONER = "practitioner"
    EXPERT = "expert"
    INNOVATOR = "innovator"


class ActivityStatus(StrEnum):
    """`ACTIVE ⇄ DORMANT`, both terminating in `DISBANDED`. See
    `policies.activity_lifecycle_policy` for the enforced transition
    table."""

    ACTIVE = "active"
    DORMANT = "dormant"
    DISBANDED = "disbanded"


class AttributionConfidence(StrEnum):
    """Derived, never set directly by a caller — see
    `policies.attribution_confidence_policy`. Reflects how much
    corroborating evidence (associated techniques/indicators,
    sophistication) supports treating this actor's attribution as
    reliable."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AssociationState(StrEnum):
    """A `ThreatActorAssociation`'s lifecycle state (M51.1). Append-only:
    a correction is a transition to `RETRACTED` plus a new `ACTIVE`
    association if the fact is re-asserted — never an in-place edit
    of the original row. `RETRACTED` is terminal (see
    `AssociationRetractionPolicy`)."""

    ACTIVE = "active"
    RETRACTED = "retracted"


class ThreatActorIntelRole(StrEnum):
    """Application-layer authorization roles for threat_actor_intel
    (M51.1 Phase 2), namespaced consistent with `exposure.ExposureRole`'s
    convention. A single linear rank (mirroring `exposure`'s
    `require_at_least`), not a new RBAC framework:
    `VIEWER` — read-only, global reads and a tenant's own associations.
    `ANALYST` — tenant-scoped association create/retract/list.
    `PLATFORM_ADMIN` — global `ThreatActor` create/mutate (ADR-M51.1-02:
    a global reference record's mutation is a platform-admin action,
    never a tenant-scoped one)."""

    VIEWER = "threat_actor_intel:viewer"
    ANALYST = "threat_actor_intel:analyst"
    PLATFORM_ADMIN = "threat_actor_intel:platform_admin"

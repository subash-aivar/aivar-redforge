"""Enumerations for the engagement domain."""

from __future__ import annotations

from enum import StrEnum


class EngagementState(StrEnum):
    DRAFT = "Draft"
    PENDING_APPROVAL = "PendingApproval"
    APPROVED = "Approved"
    ACTIVE = "Active"
    SUSPENDED = "Suspended"
    CLOSED = "Closed"
    ARCHIVED = "Archived"


class EngagementClassification(StrEnum):
    INTERNAL = "Internal"
    EXTERNAL_PENTEST = "ExternalPentest"
    PURPLE_TEAM = "PurpleTeam"
    TABLETOP_ONLY = "TabletopOnly"
    FULL_SIMULATION = "FullSimulation"


class KillSwitchState(StrEnum):
    """Field on Engagement — Redis kill-switch infra is Phase 3."""

    ARMED = "Armed"
    TRIGGERED = "Triggered"
    RELEASED = "Released"


class AuthorizationState(StrEnum):
    ACTIVE = "Active"
    SUSPENDED = "Suspended"
    REVOKED = "Revoked"
    EXPIRED = "Expired"


class ImpactCeiling(StrEnum):
    OBSERVE = "Observe"
    PROBE = "Probe"
    EXPLOIT = "Exploit"
    DESTRUCT = "Destruct"


class AuthorizationDecision(StrEnum):
    AUTHORIZED = "Authorized"
    FORBIDDEN = "Forbidden"
    DEFERRED = "Deferred"


class QuorumType(StrEnum):
    UNANIMOUS = "Unanimous"
    MAJORITY = "Majority"

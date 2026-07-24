"""Closed enums for the siem_storage bounded context (M37 §4)."""

from __future__ import annotations

from enum import StrEnum


class StorageTier(StrEnum):
    """The storage lifecycle stages (M37 §4, extended by M43E's
    Storage Foundation to distinguish "cold, still retrievable on
    demand" from "archive, terminal retention state" — additive, not a
    redefinition, per M41's governance discipline for enum evolution).
    Archive is the DR source of truth; hot/warm/cold are accelerated
    views over it."""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    ARCHIVE = "archive"


class StorageRole(StrEnum):
    """RBAC scopes for siem_storage's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model)."""

    VIEWER = "siem_storage:viewer"
    PLANNER = "siem_storage:plan"
    ADMIN = "siem_storage:admin"

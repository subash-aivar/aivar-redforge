"""Shared domain primitives used across all bounded contexts.

This package provides the foundational building blocks that every
domain entity and value object in RedForge depends on:

- EntityId: ULID-based unique identifier for all entities.
- AuditTimestamps: Immutable creation/modification timestamps.
- BaseEntity: Base class providing identity and timestamp semantics.
- utc_now: Centralized UTC timestamp factory.
"""

from redforge.shared.entity import BaseEntity
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

__all__ = [
    "AuditTimestamps",
    "BaseEntity",
    "EntityId",
    "utc_now",
]

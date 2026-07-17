"""Data Transfer Objects for the Compliance application layer."""

from __future__ import annotations

from dataclasses import dataclass

from redforge.domain.compliance.value_objects import (
    FrameworkKey,
    MappingConfidenceHint,
)
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class SeedCatalogCommand:
    """Trigger idempotent seeding of all framework adapters into the catalog.

    published_by is the platform user_id that will appear in domain events.
    auto_publish=True publishes each framework immediately after loading.
    """

    published_by: str
    auto_publish: bool = True


@dataclass(frozen=True, slots=True)
class PublishFrameworkCommand:
    """Publish a DRAFT framework in the catalog."""

    framework_key: FrameworkKey
    published_by: str


@dataclass(frozen=True, slots=True)
class RetireFrameworkCommand:
    """Retire a PUBLISHED framework."""

    framework_key: FrameworkKey
    reason: str
    retired_by: str


@dataclass(frozen=True, slots=True)
class DefineMappingCommand:
    """Define a new cross-framework ControlMapping."""

    source_requirement_id: EntityId
    target_requirement_id: EntityId
    source_framework_key: FrameworkKey
    target_framework_key: FrameworkKey
    confidence: MappingConfidenceHint
    rationale: str
    defined_by: str


@dataclass(frozen=True, slots=True)
class RevokeMappingCommand:
    """Revoke an active ControlMapping."""

    mapping_id: EntityId
    reason: str
    revoked_by: str


@dataclass(frozen=True, slots=True)
class ListFrameworksQuery:
    """Query parameters for listing frameworks."""

    status_filter: str | None = None


@dataclass(frozen=True, slots=True)
class ListRequirementsQuery:
    """Query parameters for listing controls within a framework."""

    framework_key: FrameworkKey
    search: str | None = None
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class ListMappingsQuery:
    """Query parameters for browsing cross-framework mappings."""

    source_framework_key: FrameworkKey | None = None
    target_framework_key: FrameworkKey | None = None
    active_only: bool = True
    limit: int = 200
    offset: int = 0

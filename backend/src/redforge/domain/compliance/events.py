"""Domain events for the Compliance bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.compliance.value_objects import (  # noqa: TC001
    FrameworkKey,
    MappingConfidenceHint,
)


@dataclass(frozen=True, slots=True)
class FrameworkPublished:
    """Emitted when a FrameworkDefinition transitions to PUBLISHED."""

    framework_key: FrameworkKey
    framework_name: str
    version: str
    published_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FrameworkRetired:
    """Emitted when a FrameworkDefinition transitions to RETIRED."""

    framework_key: FrameworkKey
    framework_name: str
    reason: str
    retired_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlMappingDefined:
    """Emitted when a new cross-framework ControlMapping is created."""

    mapping_id: str
    source_requirement_id: str
    target_requirement_id: str
    source_framework_key: FrameworkKey
    target_framework_key: FrameworkKey
    confidence: MappingConfidenceHint
    defined_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlMappingRevoked:
    """Emitted when an active ControlMapping is deactivated."""

    mapping_id: str
    source_requirement_id: str
    target_requirement_id: str
    reason: str
    revoked_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

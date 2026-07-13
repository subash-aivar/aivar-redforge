"""Mapper between Organization domain entity and ORM model.

This module is the only place that knows about both the domain entity
and the ORM model simultaneously. It translates in both directions:

- to_model: Domain Entity → ORM Model (for persistence)
- to_entity: ORM Model → Domain Entity (for reconstitution)

No business logic exists here. The mapper is a pure data transformation.
"""

from datetime import UTC, datetime

from redforge.domain.organizations.entity import Organization
from redforge.domain.organizations.value_objects import (
    OrganizationName,
    OrganizationPlan,
    OrganizationSlug,
    OrganizationStatus,
)
from redforge.infrastructure.database.models.organization import OrganizationModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware UTC.

    Some database drivers (e.g., SQLite) strip timezone info.
    This normalizes the datetime back to UTC-aware.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def to_model(entity: Organization) -> OrganizationModel:
    """Map a domain Organization entity to an ORM model for persistence."""
    return OrganizationModel(
        id=str(entity.id),
        name=str(entity.name),
        slug=str(entity.slug),
        status=str(entity.status),
        plan=str(entity.plan),
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
    )


def to_entity(model: OrganizationModel) -> Organization:
    """Reconstitute a domain Organization entity from an ORM model.

    This bypasses the create() factory because we are loading an existing
    entity from persistence, not creating a new one. No events should be
    emitted during reconstitution.
    """
    return Organization(
        id=EntityId.from_string(model.id),
        name=OrganizationName(model.name),
        slug=OrganizationSlug(model.slug),
        status=OrganizationStatus(model.status),
        plan=OrganizationPlan(model.plan),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at),
            updated_at=_ensure_utc(model.updated_at),
        ),
    )

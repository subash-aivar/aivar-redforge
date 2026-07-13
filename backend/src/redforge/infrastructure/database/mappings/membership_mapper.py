"""Mapper between Membership domain entity and ORM model.

No business logic here — pure data transformation, same convention as
organization_mapper.py / ai_target_mapper.py.
"""

from datetime import UTC, datetime

from redforge.domain.identity.entities import Membership
from redforge.domain.identity.value_objects import MembershipRole, MembershipStatus
from redforge.infrastructure.database.models.membership import MembershipModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def to_model(entity: Membership) -> MembershipModel:
    """Map a domain Membership entity to an ORM model for persistence."""
    return MembershipModel(
        id=str(entity.id),
        user_id=str(entity.user_id),
        organization_id=str(entity.organization_id),
        role=str(entity.role),
        status=str(entity.status),
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
    )


def to_entity(model: MembershipModel) -> Membership:
    """Reconstitute a domain Membership entity from an ORM model.

    Bypasses the create() factory (loading an existing entity, not
    creating a new one) — no events should be emitted on reconstitution.
    """
    return Membership(
        id=EntityId.from_string(model.id),
        user_id=EntityId.from_string(model.user_id),
        organization_id=EntityId.from_string(model.organization_id),
        role=MembershipRole(model.role),
        status=MembershipStatus(model.status),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at),
            updated_at=_ensure_utc(model.updated_at),
        ),
    )

"""Mapper between Invitation domain entity and ORM model.

No business logic here — pure data transformation, same convention as
membership_mapper.py.
"""

from datetime import UTC, datetime

from redforge.domain.identity.entities import Invitation
from redforge.domain.identity.value_objects import Email, InvitationStatus, MembershipRole
from redforge.infrastructure.database.models.invitation import InvitationModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def to_model(entity: Invitation) -> InvitationModel:
    """Map a domain Invitation entity to an ORM model for persistence."""
    return InvitationModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        email=str(entity.email),
        role=str(entity.role),
        invited_by_user_id=str(entity.invited_by_user_id),
        token_hash=entity.token_hash,
        status=str(entity.status),
        expires_at=entity.expires_at,
        accepted_by_user_id=(
            str(entity.accepted_by_user_id) if entity.accepted_by_user_id else None
        ),
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
    )


def to_entity(model: InvitationModel) -> Invitation:
    """Reconstitute a domain Invitation entity from an ORM model.

    Bypasses create() (loading an existing entity, not creating a new
    one) — no events should be emitted on reconstitution, and the
    plaintext token is never available here (only its hash is stored).
    """
    return Invitation(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        email=Email(model.email),
        role=MembershipRole(model.role),
        invited_by_user_id=EntityId.from_string(model.invited_by_user_id),
        token_hash=model.token_hash,
        status=InvitationStatus(model.status),
        expires_at=_ensure_utc(model.expires_at),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at),
            updated_at=_ensure_utc(model.updated_at),
        ),
        accepted_by_user_id=(
            EntityId.from_string(model.accepted_by_user_id)
            if model.accepted_by_user_id
            else None
        ),
    )

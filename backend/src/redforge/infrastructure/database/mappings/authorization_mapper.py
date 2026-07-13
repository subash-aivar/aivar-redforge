"""Mappers between Security Authorization domain entities and ORM models.

No business logic here — pure data transformation, same convention as
membership_mapper.py / organization_mapper.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.authorization.entity import AuthorizationApproval, SecurityAuthorization
from redforge.domain.authorization.value_objects import (
    ActionClass,
    ApprovalDecision,
    AuthorizationScopeEntry,
    AuthorizationStatus,
    ScopeEntityType,
    ValidityWindow,
)
from redforge.infrastructure.database.models.authorization import (
    SecurityAuthorizationApprovalModel,
    SecurityAuthorizationModel,
    SecurityAuthorizationScopeModel,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def authorization_to_model(entity: SecurityAuthorization) -> SecurityAuthorizationModel:
    return SecurityAuthorizationModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        requester_user_id=str(entity.requester_user_id),
        status=str(entity.status),
        action_classes=sorted(str(a) for a in entity.action_classes),
        valid_from=entity.validity.valid_from,
        valid_until=entity.validity.valid_until,
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
    )


def scope_to_models(entity: SecurityAuthorization) -> list[SecurityAuthorizationScopeModel]:
    return [
        SecurityAuthorizationScopeModel(
            id=str(EntityId.generate()),
            organization_id=str(entity.organization_id),
            authorization_id=str(entity.id),
            entity_type=str(scope_entry.entity_type),
            entity_id=scope_entry.entity_id,
        )
        for scope_entry in entity.scope
    ]


def authorization_to_entity(
    model: SecurityAuthorizationModel,
    scope_models: list[SecurityAuthorizationScopeModel],
) -> SecurityAuthorization:
    """Reconstitute a SecurityAuthorization from its ORM model and scope
    rows. Bypasses create() (loading an existing entity, not creating a
    new one) — no events should be emitted on reconstitution."""
    return SecurityAuthorization(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        requester_user_id=EntityId.from_string(model.requester_user_id),
        status=AuthorizationStatus(model.status),
        action_classes={ActionClass(a) for a in model.action_classes},
        scope={
            AuthorizationScopeEntry(
                entity_type=ScopeEntityType(s.entity_type), entity_id=s.entity_id,
            )
            for s in scope_models
        },
        validity=ValidityWindow(
            valid_from=_ensure_utc(model.valid_from), valid_until=_ensure_utc(model.valid_until),
        ),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at), updated_at=_ensure_utc(model.updated_at),
        ),
    )


def approval_to_model(entity: AuthorizationApproval) -> SecurityAuthorizationApprovalModel:
    return SecurityAuthorizationApprovalModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        authorization_id=str(entity.authorization_id),
        requester_user_id=str(entity.requester_user_id),
        approver_user_id=str(entity.approver_user_id) if entity.approver_user_id else None,
        decision=str(entity.decision) if entity.decision else None,
        reason=entity.reason,
        requested_at=entity.requested_at,
        decided_at=entity.decided_at,
    )


def approval_to_entity(model: SecurityAuthorizationApprovalModel) -> AuthorizationApproval:
    return AuthorizationApproval(
        id=EntityId.from_string(model.id),
        authorization_id=EntityId.from_string(model.authorization_id),
        organization_id=EntityId.from_string(model.organization_id),
        requester_user_id=EntityId.from_string(model.requester_user_id),
        requested_at=_ensure_utc(model.requested_at),
        approver_user_id=(
            EntityId.from_string(model.approver_user_id) if model.approver_user_id else None
        ),
        decision=ApprovalDecision(model.decision) if model.decision else None,
        decided_at=_ensure_utc(model.decided_at) if model.decided_at else None,
        reason=model.reason,
    )

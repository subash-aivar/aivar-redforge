"""Mapper between AITarget domain entity and ORM model."""

import json
from datetime import UTC, datetime

from redforge.domain.ai_targets.entity import AITarget
from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    Tag,
    TargetMetadata,
    TargetName,
    TargetStatus,
    TargetType,
    ValidationPolicyReference,
)
from redforge.infrastructure.database.models.ai_target import AITargetModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def to_model(entity: AITarget) -> AITargetModel:
    """Map AITarget domain entity to ORM model."""
    return AITargetModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        name=str(entity.name),
        description=entity.description,
        target_type=str(entity.target_type),
        provider=str(entity.provider),
        endpoint=str(entity.endpoint),
        auth_reference=entity.auth_reference,
        status=str(entity.status),
        tags_json=json.dumps(sorted(str(t) for t in entity.tags)),
        policies_json=json.dumps(sorted(str(p) for p in entity.policies)),
        metadata_json=json.dumps(entity.metadata.data),
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
    )


def to_entity(model: AITargetModel) -> AITarget:
    """Reconstitute AITarget domain entity from ORM model."""
    tags_list: list[str] = json.loads(model.tags_json)
    policies_list: list[str] = json.loads(model.policies_json)
    metadata_dict: dict[str, str] = json.loads(model.metadata_json)

    return AITarget(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        name=TargetName(model.name),
        description=model.description,
        target_type=TargetType(model.target_type),
        provider=Provider(model.provider),
        endpoint=EndpointUrl(model.endpoint),
        auth_reference=model.auth_reference,
        status=TargetStatus(model.status),
        tags={Tag(t) for t in tags_list},
        policies={ValidationPolicyReference(p) for p in policies_list if p},
        metadata=TargetMetadata(metadata_dict) if metadata_dict else TargetMetadata(),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at),
            updated_at=_ensure_utc(model.updated_at),
        ),
    )

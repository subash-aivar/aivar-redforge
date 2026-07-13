"""Mappers between Continuous Validation domain entities and ORM models
(M14). Pure data transformation, no business logic — matches
validation_execution_mapper.py's convention.
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.continuous_validation.entity import (
    ContinuousValidationPolicy,
    SecurityDriftEvent,
    ServiceSnapshotEntry,
    ValidationStateSnapshot,
)
from redforge.domain.continuous_validation.value_objects import (
    PolicyLifecycle,
    SecurityDriftCategory,
    ValidationCadence,
)
from redforge.domain.validation_execution.value_objects import ValidationProfile
from redforge.infrastructure.database.models.continuous_validation import (
    ContinuousValidationPolicyModel,
    SecurityDriftEventModel,
    ValidationStateSnapshotModel,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _ensure_utc_opt(dt: datetime | None) -> datetime | None:
    return _ensure_utc(dt) if dt is not None else None


def policy_to_model(entity: ContinuousValidationPolicy) -> ContinuousValidationPolicyModel:
    return ContinuousValidationPolicyModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        target_id=str(entity.target_id),
        requester_user_id=str(entity.requester_user_id),
        profile=str(entity.profile),
        cadence=str(entity.cadence),
        lifecycle=str(entity.lifecycle),
        next_due_at=entity.next_due_at,
        last_scheduled_at=entity.last_scheduled_at,
        claimed_at=entity.claimed_at,
        claim_owner=entity.claim_owner,
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
    )


def policy_to_entity(model: ContinuousValidationPolicyModel) -> ContinuousValidationPolicy:
    return ContinuousValidationPolicy(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        target_id=EntityId.from_string(model.target_id),
        requester_user_id=EntityId.from_string(model.requester_user_id),
        profile=ValidationProfile(model.profile),
        cadence=ValidationCadence(model.cadence),
        lifecycle=PolicyLifecycle(model.lifecycle),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at), updated_at=_ensure_utc(model.updated_at),
        ),
        next_due_at=_ensure_utc_opt(model.next_due_at),
        last_scheduled_at=_ensure_utc_opt(model.last_scheduled_at),
        claimed_at=_ensure_utc_opt(model.claimed_at),
        claim_owner=model.claim_owner,
    )


def snapshot_to_model(entity: ValidationStateSnapshot) -> ValidationStateSnapshotModel:
    return ValidationStateSnapshotModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        continuous_policy_id=str(entity.continuous_policy_id),
        execution_id=str(entity.execution_id),
        schema_version=entity.schema_version,
        resolved_ips=list(entity.resolved_ips),
        reachable_ports=list(entity.reachable_ports),
        services=[
            {
                "port": s.port,
                "validated_protocol": s.validated_protocol,
                "validator_id": s.validator_id,
                "tls_fingerprint_sha256": s.tls_fingerprint_sha256,
            }
            for s in entity.services
        ],
        active_condition_keys=list(entity.active_condition_keys),
        active_correlation_keys=list(entity.active_correlation_keys),
        content_fingerprint=entity.content_fingerprint,
        captured_at=entity.captured_at,
    )


def snapshot_to_entity(model: ValidationStateSnapshotModel) -> ValidationStateSnapshot:
    return ValidationStateSnapshot(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        continuous_policy_id=EntityId.from_string(model.continuous_policy_id),
        execution_id=EntityId.from_string(model.execution_id),
        schema_version=model.schema_version,
        resolved_ips=tuple(model.resolved_ips),
        reachable_ports=tuple(model.reachable_ports),
        services=tuple(
            ServiceSnapshotEntry(
                port=s["port"],
                validated_protocol=s["validated_protocol"],
                validator_id=s["validator_id"],
                tls_fingerprint_sha256=s["tls_fingerprint_sha256"],
            )
            for s in model.services
        ),
        active_condition_keys=tuple(model.active_condition_keys),
        active_correlation_keys=tuple(model.active_correlation_keys),
        content_fingerprint=model.content_fingerprint,
        captured_at=_ensure_utc(model.captured_at),
    )


def drift_event_to_model(entity: SecurityDriftEvent) -> SecurityDriftEventModel:
    return SecurityDriftEventModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        continuous_policy_id=str(entity.continuous_policy_id),
        execution_id=str(entity.execution_id),
        category=str(entity.category),
        identity_key=entity.identity_key,
        summary=entity.summary,
        detail=entity.detail,
        detected_at=entity.detected_at,
    )


def drift_event_to_entity(model: SecurityDriftEventModel) -> SecurityDriftEvent:
    return SecurityDriftEvent(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        continuous_policy_id=EntityId.from_string(model.continuous_policy_id),
        execution_id=EntityId.from_string(model.execution_id),
        category=SecurityDriftCategory(model.category),
        identity_key=model.identity_key,
        summary=model.summary,
        detail=dict(model.detail),
        detected_at=_ensure_utc(model.detected_at),
    )

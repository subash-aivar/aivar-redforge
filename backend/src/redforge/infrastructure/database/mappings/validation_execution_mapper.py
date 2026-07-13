"""Mappers between Gated Safe Active Validation domain entities and ORM
models. Pure data transformation, no business logic — matches
authorization_mapper.py's convention.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from redforge.domain.validation_execution.entity import ValidationExecution, ValidationStep
from redforge.domain.validation_execution.execution_event import ExecutionEvent
from redforge.domain.validation_execution.value_objects import (
    ErrorCategory,
    ExecutionEventType,
    ExecutionLimits,
    ExecutionStatus,
    ExecutionTrigger,
    StepSource,
    StepStatus,
    StepType,
    ValidationProfile,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _ensure_utc_opt(dt: datetime | None) -> datetime | None:
    return _ensure_utc(dt) if dt is not None else None


def execution_to_model(entity: ValidationExecution) -> ValidationExecutionModel:
    return ValidationExecutionModel(
        id=str(entity.id),
        organization_id=str(entity.organization_id),
        target_id=str(entity.target_id),
        requester_user_id=str(entity.requester_user_id),
        profile=str(entity.profile),
        status=str(entity.status),
        policy_decision_id=entity.policy_decision_id,
        policy_reason_code=entity.policy_reason_code,
        cancellation_requested=entity.cancellation_requested,
        limits=asdict(entity.limits),
        failure_reason=entity.failure_reason,
        created_at=entity.timestamps.created_at,
        updated_at=entity.timestamps.updated_at,
        started_at=entity.started_at,
        completed_at=entity.completed_at,
        trigger=str(entity.trigger),
        continuous_policy_id=(
            str(entity.continuous_policy_id) if entity.continuous_policy_id else None
        ),
        scheduled_due_at=entity.scheduled_due_at,
    )


def steps_to_models(entity: ValidationExecution) -> list[ValidationExecutionStepModel]:
    return [
        ValidationExecutionStepModel(
            id=str(step.id),
            organization_id=str(entity.organization_id),
            execution_id=str(entity.id),
            step_type=str(step.step_type),
            order_index=step.order,
            status=str(step.status),
            started_at=step.started_at,
            completed_at=step.completed_at,
            evidence=list(step.evidence),
            error_category=str(step.error_category) if step.error_category else None,
            source=str(step.source),
            adaptive_rule_id=step.adaptive_rule_id,
            adaptive_rule_version=step.adaptive_rule_version,
            source_fact_ref=step.source_fact_ref,
            validator_id=step.validator_id,
            validator_version=step.validator_version,
            protocol_validation_state=step.protocol_validation_state,
        )
        for step in entity.steps
    ]


def execution_to_entity(
    model: ValidationExecutionModel, step_models: list[ValidationExecutionStepModel],
) -> ValidationExecution:
    """Reconstitute a ValidationExecution from its ORM model and step
    rows. Bypasses create() (loading, not creating) — no events emitted."""
    steps = [
        ValidationStep(
            id=EntityId.from_string(s.id),
            step_type=StepType(s.step_type),
            order=s.order_index,
            status=StepStatus(s.status),
            started_at=_ensure_utc_opt(s.started_at),
            completed_at=_ensure_utc_opt(s.completed_at),
            evidence=tuple(s.evidence),
            error_category=ErrorCategory(s.error_category) if s.error_category else None,
            source=StepSource(s.source),
            adaptive_rule_id=s.adaptive_rule_id,
            adaptive_rule_version=s.adaptive_rule_version,
            source_fact_ref=s.source_fact_ref,
            validator_id=s.validator_id,
            validator_version=s.validator_version,
            protocol_validation_state=s.protocol_validation_state,
        )
        for s in sorted(step_models, key=lambda m: m.order_index)
    ]
    return ValidationExecution(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        target_id=EntityId.from_string(model.target_id),
        requester_user_id=EntityId.from_string(model.requester_user_id),
        profile=ValidationProfile(model.profile),
        status=ExecutionStatus(model.status),
        limits=ExecutionLimits(**model.limits),
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at), updated_at=_ensure_utc(model.updated_at),
        ),
        steps=steps,
        policy_decision_id=model.policy_decision_id,
        policy_reason_code=model.policy_reason_code,
        cancellation_requested=model.cancellation_requested,
        started_at=_ensure_utc_opt(model.started_at),
        completed_at=_ensure_utc_opt(model.completed_at),
        failure_reason=model.failure_reason,
        trigger=ExecutionTrigger(model.trigger),
        continuous_policy_id=(
            EntityId.from_string(model.continuous_policy_id)
            if model.continuous_policy_id
            else None
        ),
        scheduled_due_at=_ensure_utc_opt(model.scheduled_due_at),
    )


def event_to_model(event: ExecutionEvent) -> ValidationExecutionEventModel:
    return ValidationExecutionEventModel(
        id=str(event.id),
        organization_id=str(event.organization_id),
        execution_id=str(event.execution_id),
        sequence=event.sequence,
        event_type=str(event.event_type),
        payload=event.payload,
        occurred_at=event.occurred_at,
    )


def event_to_entity(model: ValidationExecutionEventModel) -> ExecutionEvent:
    return ExecutionEvent(
        id=EntityId.from_string(model.id),
        execution_id=EntityId.from_string(model.execution_id),
        organization_id=EntityId.from_string(model.organization_id),
        sequence=model.sequence,
        event_type=ExecutionEventType(model.event_type),
        payload=dict(model.payload),
        occurred_at=_ensure_utc(model.occurred_at),
    )

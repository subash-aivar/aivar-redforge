"""AutonomousOperationsPolicy — per-tenant autonomy / kill switch."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.evidence import (
    CONFIDENCE_FLOORS,
    DEFAULT_MIN_CONFIDENCE,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class AutonomousOperationsPolicy:
    __slots__ = (
        "_pending_events",
        "enabled_target_types",
        "kill_switch_active",
        "min_confidence_by_type",
        "review_required",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        tenant_id: TenantId,
        *,
        kill_switch_active: bool = False,
        min_confidence_by_type: dict[SuggestionTargetType, float] | None = None,
        enabled_target_types: list[SuggestionTargetType] | None = None,
        review_required: bool = True,
        updated_at: datetime | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.kill_switch_active = kill_switch_active
        self.min_confidence_by_type = dict(min_confidence_by_type or DEFAULT_MIN_CONFIDENCE)
        self.enabled_target_types = list(enabled_target_types or list(SuggestionTargetType))
        self.review_required = review_required
        self.updated_at = updated_at or datetime.now(UTC)
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def default(cls, tenant_id: TenantId) -> AutonomousOperationsPolicy:
        return cls(tenant_id)

    def min_confidence(self, target_type: SuggestionTargetType) -> float:
        return self.min_confidence_by_type.get(target_type, DEFAULT_MIN_CONFIDENCE[target_type])

    def set_min_confidence(self, target_type: SuggestionTargetType, value: float) -> None:
        floor = CONFIDENCE_FLOORS[target_type]
        if value < floor:
            raise DomainInvariantViolation(f"min_confidence below floor {floor}")
        if value > 1.0:
            raise DomainInvariantViolation("min_confidence must be <= 1.0")
        self.min_confidence_by_type[target_type] = value
        self.updated_at = datetime.now(UTC)

    def activate_kill_switch(self) -> None:
        self.kill_switch_active = True
        self.updated_at = datetime.now(UTC)

    def reset_kill_switch(self) -> None:
        self.kill_switch_active = False
        self.updated_at = datetime.now(UTC)

    def allows(self, target_type: SuggestionTargetType) -> bool:
        return not self.kill_switch_active and target_type in self.enabled_target_types

"""DetectionRule aggregate — a versioned rule definition (M37 §2.2).

Owns rule *definition* and lifecycle only. Evaluation itself is a
separate concern (`IDetectionEvaluator`, M37 §5), and correlation-rule
execution belongs to `siem_correlation`, not this aggregate (M37 §5
point 2: "siem_detection owns the rule definition, siem_correlation
owns execution").
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_detection.domain.events.detection_events import (
    DetectionRuleActivated,
    DetectionRuleDeprecated,
    DetectionRuleVersionPublished,
)
from siem_detection.domain.exceptions.domain_exceptions import (
    EmptyRuleBodyError,
    EmptyRuleNameError,
    InvalidRuleTransition,
    TenantMismatch,
)
from siem_detection.domain.value_objects.enums import DetectionRuleShape, DetectionRuleStatus

if TYPE_CHECKING:
    from datetime import datetime

    from siem_detection.domain.events.base import BaseDomainEvent
    from siem_detection.domain.value_objects.identifiers import DetectionRuleId, TenantId


class DetectionRule:
    __slots__ = (
        "_pending_events",
        "created_at",
        "name",
        "rule_body",
        "rule_id",
        "shape",
        "status",
        "tenant_id",
        "version",
    )

    def __init__(
        self,
        rule_id: DetectionRuleId,
        tenant_id: TenantId | None,
        name: str,
        shape: DetectionRuleShape,
        rule_body: str,
        status: DetectionRuleStatus,
        version: int,
        created_at: datetime,
    ) -> None:
        self.rule_id = rule_id
        self.tenant_id = tenant_id
        self.name = name
        self.shape = shape
        self.rule_body = rule_body
        self.status = status
        self.version = version
        self.created_at = created_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId | None) -> None:
        """A platform-global rule (`tenant_id is None`) may be operated
        on by any tenant context; a tenant-owned rule may only be
        operated on by its own tenant."""
        if self.tenant_id is not None and tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _scope_id(self) -> str:
        return str(self.tenant_id) if self.tenant_id is not None else "platform"

    @classmethod
    def draft(
        cls,
        rule_id: DetectionRuleId,
        tenant_id: TenantId | None,
        name: str,
        shape: DetectionRuleShape,
        rule_body: str,
        now: datetime,
    ) -> DetectionRule:
        if not name.strip():
            raise EmptyRuleNameError()
        if not rule_body.strip():
            raise EmptyRuleBodyError()
        return cls(
            rule_id=rule_id,
            tenant_id=tenant_id,
            name=name.strip(),
            shape=shape,
            rule_body=rule_body,
            status=DetectionRuleStatus.DRAFT,
            version=1,
            created_at=now,
        )

    def publish_version(self, tenant_id: TenantId | None, rule_body: str, now: datetime) -> None:
        """Publish a new rule-body version. Parsing/validation of
        `rule_body` against the rule's shape (e.g. Sigma syntax) is an
        application-layer concern (M37 §5's "parse-once, evaluate-native"
        design) — this aggregate enforces only its own invariants."""
        self._assert_tenant(tenant_id)
        if self.status == DetectionRuleStatus.DEPRECATED:
            raise InvalidRuleTransition(self.status.value, "publish_version")
        if not rule_body.strip():
            raise EmptyRuleBodyError()
        self.rule_body = rule_body
        self.version += 1
        self._emit(
            DetectionRuleVersionPublished(
                tenant_id=self._scope_id(),
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                occurred_at=now,
                rule_version=self.version,
            )
        )

    def activate(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status != DetectionRuleStatus.DRAFT:
            raise InvalidRuleTransition(self.status.value, DetectionRuleStatus.ACTIVE.value)
        self.status = DetectionRuleStatus.ACTIVE
        self._emit(
            DetectionRuleActivated(
                tenant_id=self._scope_id(),
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                occurred_at=now,
                rule_version=self.version,
            )
        )

    def deprecate(self, tenant_id: TenantId | None, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status == DetectionRuleStatus.DEPRECATED:
            raise InvalidRuleTransition(self.status.value, DetectionRuleStatus.DEPRECATED.value)
        if not reason.strip():
            raise ValueError("deprecation reason must be a non-empty string")
        self.status = DetectionRuleStatus.DEPRECATED
        self._emit(
            DetectionRuleDeprecated(
                tenant_id=self._scope_id(),
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                occurred_at=now,
                rule_version=self.version,
                reason=reason.strip(),
            )
        )

"""ACL translators — ADR-M35-007. Isolated from upstream domain types."""

from __future__ import annotations

from dataclasses import dataclass

from automated_action.domain.value_objects.refs import TriggerRef


@dataclass(frozen=True, slots=True)
class DetectionFindingEscalatedPayload:
    finding_id: str
    tenant_id: str
    severity: str
    rule_id: str
    asset_ref: str | None
    technique_id: str | None
    escalated_at: str


@dataclass(frozen=True, slots=True)
class IncidentContainedPayload:
    incident_id: str
    tenant_id: str
    severity: str
    contained_at: str


@dataclass(frozen=True, slots=True)
class ExposureThresholdBreachedPayload:
    exposure_id: str
    tenant_id: str
    severity: str
    breached_at: str


@dataclass(frozen=True, slots=True)
class AutomationTriggerEvent:
    source_context: str
    source_event_id: str
    tenant_id: str
    severity_hint: str
    asset_ref: str | None
    source_event_type: str


class M28FindingTriggerTranslator:
    def to_trigger_event(self, payload: DetectionFindingEscalatedPayload) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context="M28_FINDING",
            source_event_id=payload.finding_id,
            tenant_id=payload.tenant_id,
            severity_hint=payload.severity,
            asset_ref=payload.asset_ref,
            source_event_type="DetectionFindingEscalated",
        )


class M34IncidentTriggerTranslator:
    def to_trigger_event(self, payload: IncidentContainedPayload) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context="M34_INCIDENT",
            source_event_id=payload.incident_id,
            tenant_id=payload.tenant_id,
            severity_hint=payload.severity,
            asset_ref=None,
            source_event_type="IncidentContained",
        )


class M32ExposureTriggerTranslator:
    def to_trigger_event(self, payload: ExposureThresholdBreachedPayload) -> AutomationTriggerEvent:
        return AutomationTriggerEvent(
            source_context="M32_EXPOSURE",
            source_event_id=payload.exposure_id,
            tenant_id=payload.tenant_id,
            severity_hint=payload.severity,
            asset_ref=None,
            source_event_type="ExposureThresholdBreached",
        )


def to_trigger_ref(event: AutomationTriggerEvent) -> TriggerRef:
    return TriggerRef(event.source_context, event.source_event_type, event.source_event_id)

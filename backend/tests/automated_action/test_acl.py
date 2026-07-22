from __future__ import annotations

from automated_action.infrastructure.acl.trigger_translators import (
    DetectionFindingEscalatedPayload,
    ExposureThresholdBreachedPayload,
    IncidentContainedPayload,
    M28FindingTriggerTranslator,
    M32ExposureTriggerTranslator,
    M34IncidentTriggerTranslator,
)


def test_m28_translator() -> None:
    event = M28FindingTriggerTranslator().to_trigger_event(
        DetectionFindingEscalatedPayload(
            "f1", "t1", "HIGH", "r1", "a1", "T1059", "2026-01-01T00:00:00Z"
        )
    )
    assert event.source_context == "M28_FINDING"
    assert event.source_event_id == "f1"


def test_m34_translator() -> None:
    event = M34IncidentTriggerTranslator().to_trigger_event(
        IncidentContainedPayload("i1", "t1", "P2_HIGH", "2026-01-01T00:00:00Z")
    )
    assert event.source_context == "M34_INCIDENT"


def test_m32_translator() -> None:
    event = M32ExposureTriggerTranslator().to_trigger_event(
        ExposureThresholdBreachedPayload("e1", "t1", "HIGH", "2026-01-01T00:00:00Z")
    )
    assert event.source_context == "M32_EXPOSURE"

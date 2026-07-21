from __future__ import annotations

from exposure_reporting.domain.services.narrative_template_service import (
    ALL_TEMPLATE_IDS,
    compute_dominant_amplifier,
    render_narrative,
    select_template,
)
from exposure_reporting.domain.value_objects.enums import NarrativeTemplateId


def test_all_seven_templates_selectable() -> None:
    mapping = {
        "KevPresent": NarrativeTemplateId.CRITICAL_EXPLOIT_AVAILABILITY,
        "ThreatActorMatch": NarrativeTemplateId.ACTIVE_THREAT_ACTOR_TARGETING,
        "ConfirmedExploitation": NarrativeTemplateId.CONFIRMED_ACTIVE_EXPLOITATION,
        "DetectionGap": NarrativeTemplateId.DETECTION_COVERAGE_CRITICAL_GAP,
        "InternetExposure": NarrativeTemplateId.INTERNET_ATTACK_SURFACE_EXPANSION,
        "AISystemRisk": NarrativeTemplateId.AI_SYSTEM_EXPOSURE_RISK,
        None: NarrativeTemplateId.GENERAL_EXPOSURE_ACCUMULATION,
    }
    for amp, expected in mapping.items():
        assert select_template(amp) == expected
    assert len(ALL_TEMPLATE_IDS) == 7


def test_dominant_amplifier_by_weight_prevalence() -> None:
    dominant = compute_dominant_amplifier(
        {"KevPresent": 1.0, "DetectionGap": 3.5, "InternetExposure": 0.5}
    )
    assert dominant == "DetectionGap"


def test_render_narrative_deterministic() -> None:
    slots = {
        "tenant_label": "t1",
        "tenant_score": 4.5,
        "asset_count": 3,
        "generated_at": "2026-07-21T00:00:00+00:00",
    }
    a = render_narrative(NarrativeTemplateId.CRITICAL_EXPLOIT_AVAILABILITY, slots)
    b = render_narrative(NarrativeTemplateId.CRITICAL_EXPLOIT_AVAILABILITY, slots)
    assert a == b
    assert "4.50" in a

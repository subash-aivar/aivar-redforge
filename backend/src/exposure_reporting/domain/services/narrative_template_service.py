"""Deterministic narrative template selection — ADR-M32-005."""

from __future__ import annotations

from exposure_reporting.domain.value_objects.enums import NarrativeTemplateId

# Amplifier type strings match exposure RiskAmplifierType values.
_TEMPLATE_BY_AMPLIFIER: dict[str, NarrativeTemplateId] = {
    "KevPresent": NarrativeTemplateId.CRITICAL_EXPLOIT_AVAILABILITY,
    "ThreatActorMatch": NarrativeTemplateId.ACTIVE_THREAT_ACTOR_TARGETING,
    "ConfirmedExploitation": NarrativeTemplateId.CONFIRMED_ACTIVE_EXPLOITATION,
    "DetectionGap": NarrativeTemplateId.DETECTION_COVERAGE_CRITICAL_GAP,
    "InternetExposure": NarrativeTemplateId.INTERNET_ATTACK_SURFACE_EXPANSION,
    "AISystemRisk": NarrativeTemplateId.AI_SYSTEM_EXPOSURE_RISK,
}

_NARRATIVE_BODIES: dict[NarrativeTemplateId, str] = {
    NarrativeTemplateId.CRITICAL_EXPLOIT_AVAILABILITY: (
        "Board Risk Summary: Known exploited vulnerabilities (KEV) dominate the exposure "
        "profile for {tenant_label}. Aggregate exposure score is {tenant_score:.2f} across "
        "{asset_count} scoreable assets. Immediate remediation of KEV-amplified assets is "
        "recommended. Generated at {generated_at}."
    ),
    NarrativeTemplateId.ACTIVE_THREAT_ACTOR_TARGETING: (
        "Board Risk Summary: Threat actor targeting is the dominant amplifier. "
        "Exposure score {tenant_score:.2f} across {asset_count} assets indicates active "
        "adversary interest. Align detection and hardening with matched TTPs. "
        "Generated at {generated_at}."
    ),
    NarrativeTemplateId.CONFIRMED_ACTIVE_EXPLOITATION: (
        "Board Risk Summary: Confirmed exploitation signals elevate risk. "
        "Tenant exposure score {tenant_score:.2f} across {asset_count} assets. "
        "Prioritize containment and forensic validation. Generated at {generated_at}."
    ),
    NarrativeTemplateId.DETECTION_COVERAGE_CRITICAL_GAP: (
        "Board Risk Summary: Detection coverage gaps amplify exposure. "
        "Score {tenant_score:.2f} across {asset_count} assets. Close coverage on "
        "techniques linked to open exposures. Generated at {generated_at}."
    ),
    NarrativeTemplateId.INTERNET_ATTACK_SURFACE_EXPANSION: (
        "Board Risk Summary: Internet-facing attack surface expansion dominates risk. "
        "Exposure score {tenant_score:.2f} across {asset_count} assets. Reduce public "
        "exposure and enforce perimeter controls. Generated at {generated_at}."
    ),
    NarrativeTemplateId.AI_SYSTEM_EXPOSURE_RISK: (
        "Board Risk Summary: AI system exposure is the dominant pattern. "
        "Score {tenant_score:.2f} across {asset_count} assets. Strengthen AI posture "
        "and agent governance controls. Generated at {generated_at}."
    ),
    NarrativeTemplateId.GENERAL_EXPOSURE_ACCUMULATION: (
        "Board Risk Summary: Exposure is accumulating across multiple amplifier classes "
        "without a single dominant pattern. Aggregate score {tenant_score:.2f} across "
        "{asset_count} assets. Pursue portfolio remediation. Generated at {generated_at}."
    ),
}


def select_template(dominant_amplifier_type: str | None) -> NarrativeTemplateId:
    if dominant_amplifier_type is None:
        return NarrativeTemplateId.GENERAL_EXPOSURE_ACCUMULATION
    return _TEMPLATE_BY_AMPLIFIER.get(
        dominant_amplifier_type, NarrativeTemplateId.GENERAL_EXPOSURE_ACCUMULATION
    )


def render_narrative(template_id: NarrativeTemplateId, slots: dict[str, object]) -> str:
    body = _NARRATIVE_BODIES[template_id]
    return body.format(**slots)


def compute_dominant_amplifier(
    amplifier_weight_prevalence: dict[str, float],
) -> str | None:
    """Dominant = highest (weight x prevalence) across active amplifiers."""
    if not amplifier_weight_prevalence:
        return None
    return max(amplifier_weight_prevalence.items(), key=lambda kv: kv[1])[0]


ALL_TEMPLATE_IDS: tuple[NarrativeTemplateId, ...] = tuple(NarrativeTemplateId)

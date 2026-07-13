"""Rule-based recommendation generation.

RecommendationGenerator is stateless. Each rule is a pure function
registered in a dict — no switch statements.

Rules produce Recommendation objects from IntelligenceContext + derived
signals (insights, coverage gaps, security gaps).

Deduplication: recommendations are keyed by (org, target, category, rule_id).
The highest-priority-score recommendation wins when a duplicate key appears.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from redforge.application.intelligence.remediation_planner import RemediationPlanner
from redforge.domain.intelligence.entity import Recommendation
from redforge.domain.intelligence.value_objects import (
    RecommendationCategory,
    RecommendationEvidence,
    RecommendationPriority,
)

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import (
        IntelligenceContext,
    )
    from redforge.domain.intelligence.entity import SecurityInsight
    from redforge.domain.intelligence.value_objects import AttackCoverageGap, SecurityGap

# Rule signature: produces list of Recommendations (no side effects)
_RuleFn = Callable[
    [
        "IntelligenceContext",
        "list[SecurityInsight]",
        "list[AttackCoverageGap]",
        "list[SecurityGap]",
        RemediationPlanner,
    ],
    "list[Recommendation]",
]

_PLANNER = RemediationPlanner()

# Priority → numeric score for deduplication comparison
_PRIORITY_SCORE: dict[RecommendationPriority, float] = {
    RecommendationPriority.CRITICAL: 100.0,
    RecommendationPriority.HIGH: 75.0,
    RecommendationPriority.MEDIUM: 50.0,
    RecommendationPriority.LOW: 25.0,
}

_RISK_PRIORITY_MAP: dict[str, RecommendationPriority] = {
    "critical": RecommendationPriority.CRITICAL,
    "high": RecommendationPriority.HIGH,
    "medium": RecommendationPriority.MEDIUM,
    "low": RecommendationPriority.LOW,
    "informational": RecommendationPriority.LOW,
}


class RecommendationGenerator:
    """Stateless service: apply rules to produce deduplicated Recommendations.

    Usage:
        gen = RecommendationGenerator()
        recs = gen.generate(context, insights, coverage_gaps, security_gaps)
    """

    def __init__(
        self,
        planner: RemediationPlanner | None = None,
        extra_rules: dict[str, _RuleFn] | None = None,
    ) -> None:
        self._planner = planner or _PLANNER
        self._rules: dict[str, _RuleFn] = {
            "critical-risk-rule": _critical_risk_rule,
            "high-risk-rule": _high_risk_rule,
            "coverage-gap-rule": _coverage_gap_rule,
            "configuration-drift-rule": _configuration_drift_rule,
            "prompt-security-rule": _prompt_security_rule,
            "agent-security-rule": _agent_security_rule,
            "tool-security-rule": _tool_security_rule,
            "mcp-security-rule": _mcp_security_rule,
            "policy-weakness-rule": _policy_weakness_rule,
            "stale-target-rule": _stale_target_rule,
            "operational-improvement-rule": _operational_improvement_rule,
        }
        if extra_rules:
            self._rules.update(extra_rules)

    def generate(
        self,
        context: IntelligenceContext,
        insights: list[SecurityInsight],
        coverage_gaps: list[AttackCoverageGap],
        security_gaps: list[SecurityGap],
    ) -> list[Recommendation]:
        raw: list[Recommendation] = []
        for rule_fn in self._rules.values():
            raw.extend(rule_fn(context, insights, coverage_gaps, security_gaps, self._planner))

        return _deduplicate(raw)


# ─── Rule implementations ─────────────────────────────────────────────────────


def _critical_risk_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Critical risk incidents → CRITICAL_SECURITY_RISK recommendation per target."""
    results: list[Recommendation] = []
    critical_incidents = [i for i in context.risk_incidents if i.priority == "critical"]
    for incident in critical_incidents:
        for target_id in incident.target_ids:
            if target_id not in context.target_ids:
                continue
            rec, _ = Recommendation.create(
                organization_id=context.organization_id,
                target_id=target_id,
                category=RecommendationCategory.CRITICAL_SECURITY_RISK,
                priority=RecommendationPriority.CRITICAL,
                priority_score=100.0 + incident.risk_score,
                title=f"Critical Security Risk: {incident.title}",
                description=(
                    f"A critical-severity risk incident (score {incident.risk_score:.1f}/10) "
                    f"was detected on this target. Immediate action required. "
                    f"Attack types involved: {', '.join(list(incident.attack_types)[:3])}."
                ),
                evidence=RecommendationEvidence(
                    risk_incident_ids=(incident.incident_id,),
                    finding_ids=incident.finding_ids,
                    evidence_chain_ids=incident.evidence_chain_ids,
                    rationale=(
                        f"Risk score {incident.risk_score:.1f}/10 exceeds critical threshold (9.0)."
                    ),
                ),
                remediation_steps=planner.plan(RecommendationCategory.CRITICAL_SECURITY_RISK),
                rule_id="critical-risk-rule",
            )
            results.append(rec)
    return results


def _high_risk_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """High-priority incidents with attack-type-specific recommendations."""
    results: list[Recommendation] = []
    high_incidents = [i for i in context.risk_incidents if i.priority == "high"]

    # attack type → category dispatcher
    _cat_for_attack: dict[str, RecommendationCategory] = {
        "prompt_injection": RecommendationCategory.PROMPT_SECURITY,
        "jailbreak": RecommendationCategory.PROMPT_SECURITY,
        "data_exfiltration": RecommendationCategory.CRITICAL_SECURITY_RISK,
        "agent": RecommendationCategory.AGENT_SECURITY,
        "tool": RecommendationCategory.TOOL_SECURITY,
        "mcp": RecommendationCategory.MCP_SECURITY,
        "rag": RecommendationCategory.RAG_SECURITY,
        "memory": RecommendationCategory.MEMORY_SECURITY,
    }

    for incident in high_incidents:
        category = RecommendationCategory.CRITICAL_SECURITY_RISK
        for attack_type in incident.attack_types:
            for key, cat in _cat_for_attack.items():
                if key in attack_type.lower():
                    category = cat
                    break
            if category != RecommendationCategory.CRITICAL_SECURITY_RISK:
                break

        for target_id in incident.target_ids:
            if target_id not in context.target_ids:
                continue
            rec, _ = Recommendation.create(
                organization_id=context.organization_id,
                target_id=target_id,
                category=category,
                priority=RecommendationPriority.HIGH,
                priority_score=75.0 + incident.risk_score,
                title=f"High Risk: {incident.title}",
                description=(
                    f"A high-severity risk incident (score {incident.risk_score:.1f}/10) "
                    f"requires remediation within 72 hours."
                ),
                evidence=RecommendationEvidence(
                    risk_incident_ids=(incident.incident_id,),
                    finding_ids=incident.finding_ids,
                    rationale=f"Risk score {incident.risk_score:.1f}/10 (high threshold: 7.0).",
                ),
                remediation_steps=planner.plan(category),
                rule_id="high-risk-rule",
            )
            results.append(rec)
    return results


def _coverage_gap_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Coverage gaps → COVERAGE_GAP recommendation per under-covered target."""
    results: list[Recommendation] = []
    for gap in coverage_gaps:
        if gap.coverage_rate >= 0.75:
            continue
        priority = gap.gap_severity
        score = _PRIORITY_SCORE[priority]
        missing_list = ", ".join(sorted(gap.missing_categories)[:5])
        rec, _ = Recommendation.create(
            organization_id=context.organization_id,
            target_id=gap.target_id,
            category=RecommendationCategory.COVERAGE_GAP,
            priority=priority,
            priority_score=score,
            title=(
                f"Attack Coverage Gap: {len(gap.missing_categories)} "
                f"Categories Untested ({gap.coverage_rate:.0%} coverage)"
            ),
            description=(
                f"Target has only tested {len(gap.tested_categories)} of "
                f"{gap.total_categories} categories ({gap.coverage_rate:.0%} coverage). "
                f"Missing: {missing_list}"
                + (" and more" if len(gap.missing_categories) > 5 else "")
                + "."
            ),
            evidence=RecommendationEvidence(
                snapshot_ids=(),
                rationale=f"Coverage rate {gap.coverage_rate:.0%} is below 75% threshold.",
            ),
            remediation_steps=planner.plan(RecommendationCategory.COVERAGE_GAP),
            rule_id="coverage-gap-rule",
        )
        results.append(rec)
    return results


def _configuration_drift_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Significant drift events → CONFIGURATION_DRIFT recommendation."""
    results: list[Recommendation] = []
    seen_targets: set[str] = set()
    for drift in context.drift_events:
        if not drift.is_significant or drift.target_id in seen_targets:
            continue
        if drift.target_id not in context.target_ids:
            continue
        seen_targets.add(drift.target_id)
        drift_list = ", ".join(drift.drift_types[:3])
        rec, _ = Recommendation.create(
            organization_id=context.organization_id,
            target_id=drift.target_id,
            category=RecommendationCategory.CONFIGURATION_DRIFT,
            priority=RecommendationPriority.HIGH,
            priority_score=80.0,
            title=f"Configuration Drift Detected: {drift_list}",
            description=(
                f"Significant configuration changes detected on this target "
                f"({drift_list}). Security posture may have changed. "
                f"Re-validation required to confirm impact."
            ),
            evidence=RecommendationEvidence(
                snapshot_ids=(drift.source_snapshot_id, drift.target_snapshot_id),
                rationale=f"Significant drift types: {', '.join(drift.drift_types)}",
            ),
            remediation_steps=planner.plan(RecommendationCategory.CONFIGURATION_DRIFT),
            rule_id="configuration-drift-rule",
        )
        results.append(rec)
    return results


def _prompt_security_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Prompt injection / jailbreak findings → PROMPT_SECURITY recommendation."""
    results: list[Recommendation] = []
    prompt_categories = {"prompt_injection", "jailbreak", "indirect_prompt_injection"}
    seen: set[str] = set()
    for finding in context.findings:
        cat = finding.attack_category.lower().replace(" ", "_")
        if not any(p in cat for p in prompt_categories):
            continue
        if finding.target_id in seen or finding.target_id not in context.target_ids:
            continue
        seen.add(finding.target_id)
        target_findings = [
            f for f in context.findings
            if f.target_id == finding.target_id
            and any(p in f.attack_category.lower() for p in prompt_categories)
        ]
        priority = (
            RecommendationPriority.CRITICAL
            if any(f.severity == "critical" for f in target_findings)
            else RecommendationPriority.HIGH
        )
        rec, _ = Recommendation.create(
            organization_id=context.organization_id,
            target_id=finding.target_id,
            category=RecommendationCategory.PROMPT_SECURITY,
            priority=priority,
            priority_score=_PRIORITY_SCORE[priority] + 5.0,
            title="Prompt Injection Vulnerability Detected",
            description=(
                f"This target has {len(target_findings)} open finding(s) related "
                f"to prompt injection or jailbreak attacks. The system prompt and "
                f"input handling require hardening."
            ),
            evidence=RecommendationEvidence(
                finding_ids=tuple(f.finding_id for f in target_findings[:10]),
                rationale="Open findings for prompt injection / jailbreak attack categories.",
            ),
            remediation_steps=planner.plan(RecommendationCategory.PROMPT_SECURITY),
            rule_id="prompt-security-rule",
        )
        results.append(rec)
    return results


def _agent_security_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Insights with CORRELATION type touching agent vectors → AGENT_SECURITY."""
    results: list[Recommendation] = []
    from redforge.domain.intelligence.value_objects import InsightType

    agent_insights = [i for i in insights if i.insight_type == InsightType.CORRELATION]
    seen: set[str] = set()
    for insight in agent_insights:
        for target_id in insight.affected_targets:
            if target_id in seen or target_id not in context.target_ids:
                continue
            seen.add(target_id)
            rec, _ = Recommendation.create(
                organization_id=context.organization_id,
                target_id=target_id,
                category=RecommendationCategory.AGENT_SECURITY,
                priority=RecommendationPriority.HIGH,
                priority_score=78.0,
                title="Cross-Target Agent Security Pattern Detected",
                description=(
                    f"Security insight '{insight.title}' indicates a correlated "
                    f"vulnerability pattern affecting this target and others. "
                    f"Agent security controls need strengthening."
                ),
                evidence=RecommendationEvidence(
                    insight_ids=(insight.id,),
                    risk_incident_ids=insight.supporting_incident_ids,
                    rationale=insight.description,
                ),
                remediation_steps=planner.plan(RecommendationCategory.AGENT_SECURITY),
                rule_id="agent-security-rule",
            )
            results.append(rec)
    return results


def _tool_security_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Tool-related attack categories in findings → TOOL_SECURITY."""
    tool_patterns = {"tool_abuse", "tool_misuse", "tool_chain", "tool_injection"}
    results: list[Recommendation] = []
    seen: set[str] = set()
    for finding in context.findings:
        cat_lower = finding.attack_category.lower().replace(" ", "_")
        if not any(p in cat_lower for p in tool_patterns):
            continue
        if finding.target_id in seen or finding.target_id not in context.target_ids:
            continue
        seen.add(finding.target_id)
        rec, _ = Recommendation.create(
            organization_id=context.organization_id,
            target_id=finding.target_id,
            category=RecommendationCategory.TOOL_SECURITY,
            priority=RecommendationPriority.HIGH,
            priority_score=72.0,
            title="Tool Security Vulnerability Detected",
            description=(
                "This target has findings related to tool abuse or tool chain attacks. "
                "Tool permission model and output validation require hardening."
            ),
            evidence=RecommendationEvidence(
                finding_ids=(finding.finding_id,),
                rationale="Open findings for tool-related attack categories.",
            ),
            remediation_steps=planner.plan(RecommendationCategory.TOOL_SECURITY),
            rule_id="tool-security-rule",
        )
        results.append(rec)
    return results


def _mcp_security_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """MCP-related attack categories in findings → MCP_SECURITY."""
    mcp_patterns = {"mcp", "model_context_protocol"}
    results: list[Recommendation] = []
    seen: set[str] = set()
    for finding in context.findings:
        cat_lower = finding.attack_category.lower().replace(" ", "_")
        if not any(p in cat_lower for p in mcp_patterns):
            continue
        if finding.target_id in seen or finding.target_id not in context.target_ids:
            continue
        seen.add(finding.target_id)
        rec, _ = Recommendation.create(
            organization_id=context.organization_id,
            target_id=finding.target_id,
            category=RecommendationCategory.MCP_SECURITY,
            priority=RecommendationPriority.HIGH,
            priority_score=78.0,
            title="MCP Server Security Vulnerability Detected",
            description=(
                "This target has findings related to MCP server vulnerabilities. "
                "MCP resource access, tool permissions, and server auth require hardening."
            ),
            evidence=RecommendationEvidence(
                finding_ids=(finding.finding_id,),
                rationale="Open findings for MCP-related attack categories.",
            ),
            remediation_steps=planner.plan(RecommendationCategory.MCP_SECURITY),
            rule_id="mcp-security-rule",
        )
        results.append(rec)
    return results


def _policy_weakness_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """PATTERN insights (repeated failures) → POLICY_WEAKNESS recommendation."""
    from redforge.domain.intelligence.value_objects import InsightType

    pattern_insights = [
        i for i in insights
        if i.insight_type in (InsightType.PATTERN, InsightType.REGRESSION)
    ]
    if not pattern_insights:
        return []

    # One org-level policy weakness recommendation if patterns detected
    rec, _ = Recommendation.create(
        organization_id=context.organization_id,
        target_id="",  # org-level recommendation
        category=RecommendationCategory.POLICY_WEAKNESS,
        priority=RecommendationPriority.MEDIUM,
        priority_score=55.0,
        title=f"Validation Policy Gaps: {len(pattern_insights)} Persistent Pattern(s) Detected",
        description=(
            f"{len(pattern_insights)} security pattern insight(s) indicate that "
            f"the current validation policy is not catching or preventing recurring "
            f"vulnerabilities. Policy coverage and frequency need review."
        ),
        evidence=RecommendationEvidence(
            insight_ids=tuple(i.id for i in pattern_insights),
            rationale="Persistent vulnerability patterns indicate policy gaps.",
        ),
        remediation_steps=planner.plan(RecommendationCategory.POLICY_WEAKNESS),
        rule_id="policy-weakness-rule",
    )
    return [rec]


def _stale_target_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Targets with no recent validation → OPERATIONAL_IMPROVEMENT."""
    from redforge.domain.intelligence.value_objects import GapType

    temporal_gaps = [g for g in security_gaps if g.gap_type == GapType.TEMPORAL_COVERAGE]
    if not temporal_gaps:
        return []

    gap = temporal_gaps[0]
    rec, _ = Recommendation.create(
        organization_id=context.organization_id,
        target_id="",
        category=RecommendationCategory.OPERATIONAL_IMPROVEMENT,
        priority=gap.severity,
        priority_score=_PRIORITY_SCORE[gap.severity] + 5.0,
        title=f"{len(gap.affected_targets)} Target(s) Without Recent Validation",
        description=gap.description,
        evidence=RecommendationEvidence(
            rationale="Targets exceed stale validation threshold.",
        ),
        remediation_steps=planner.plan(RecommendationCategory.OPERATIONAL_IMPROVEMENT),
        rule_id="stale-target-rule",
    )
    return [rec]


def _operational_improvement_rule(
    context: IntelligenceContext,
    insights: list[SecurityInsight],
    coverage_gaps: list[AttackCoverageGap],
    security_gaps: list[SecurityGap],
    planner: RemediationPlanner,
) -> list[Recommendation]:
    """Stale critical findings from ANOMALY insights → OPERATIONAL_IMPROVEMENT."""
    from redforge.domain.intelligence.value_objects import InsightType

    stale_insights = [
        i for i in insights
        if i.insight_type == InsightType.ANOMALY and "stale" in i.title.lower()
    ]
    if not stale_insights:
        return []

    insight = stale_insights[0]
    rec, _ = Recommendation.create(
        organization_id=context.organization_id,
        target_id="",
        category=RecommendationCategory.OPERATIONAL_IMPROVEMENT,
        priority=RecommendationPriority.HIGH,
        priority_score=72.0,
        title=insight.title,
        description=insight.description,
        evidence=RecommendationEvidence(
            insight_ids=(insight.id,),
            finding_ids=insight.supporting_finding_ids,
            rationale="Critical findings unresolved beyond SLA threshold.",
        ),
        remediation_steps=planner.plan(RecommendationCategory.OPERATIONAL_IMPROVEMENT),
        rule_id="operational-improvement-rule",
    )
    return [rec]


# ─── Deduplication ────────────────────────────────────────────────────────────


def _deduplicate(recommendations: list[Recommendation]) -> list[Recommendation]:
    """Keep the highest-score recommendation for each (org, target, category, rule_id) key."""
    best: dict[str, Recommendation] = {}
    for rec in recommendations:
        key = rec.deduplication_key
        existing = best.get(key)
        if existing is None or rec.priority_score > existing.priority_score:
            best[key] = rec
    return list(best.values())

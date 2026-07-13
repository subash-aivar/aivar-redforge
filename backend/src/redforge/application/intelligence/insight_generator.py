"""Insight generation — recognizes patterns, anomalies, and trends.

InsightGenerator is stateless. It applies deterministic rules to produce
SecurityInsight objects. No LLM. No ML. Pure rule-based pattern matching.

Rules (all implemented in the _rules registry):
  1. persistent-attack-pattern: same attack category fails repeatedly across runs
  2. cross-target-vulnerability: same category fails across multiple targets
  3. security-degradation-trend: vulnerability rate increasing over snapshots
  4. regression-after-stable: baseline regression with no configuration change
  5. drift-after-regression: regression coincides with configuration drift
  6. stale-critical-finding: critical finding open for > 7 days
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import TYPE_CHECKING

from redforge.domain.intelligence.entity import SecurityInsight
from redforge.domain.intelligence.value_objects import InsightType

if TYPE_CHECKING:
    from redforge.application.intelligence.contracts import (
        FindingInput,
        IntelligenceContext,
    )

# Rule signature: (IntelligenceContext) -> list[SecurityInsight]
_RuleFn = Callable[["IntelligenceContext"], list[SecurityInsight]]


class InsightGenerator:
    """Stateless service: recognize security insights from context.

    All rules are registered via a dict — no switch statements.
    Add new rules by injecting additional _RuleFn callables.

    Usage:
        gen = InsightGenerator()
        insights = gen.generate(context)
    """

    def __init__(self, extra_rules: dict[str, _RuleFn] | None = None) -> None:
        self._rules: dict[str, _RuleFn] = {
            "persistent-attack-pattern": _persistent_attack_pattern,
            "cross-target-vulnerability": _cross_target_vulnerability,
            "security-degradation-trend": _security_degradation_trend,
            "regression-after-stable": _regression_after_stable,
            "drift-coincides-with-regression": _drift_coincides_with_regression,
            "stale-critical-finding": _stale_critical_finding,
        }
        if extra_rules:
            self._rules.update(extra_rules)

    def generate(self, context: IntelligenceContext) -> list[SecurityInsight]:
        insights: list[SecurityInsight] = []
        for rule_fn in self._rules.values():
            insights.extend(rule_fn(context))
        return insights


# ─── Rule implementations ────────────────────────────────────────────────────


def _persistent_attack_pattern(context: IntelligenceContext) -> list[SecurityInsight]:
    """Detect: same attack category fails in >= 3 runs for a target."""
    results: list[SecurityInsight] = []
    for target_id in context.target_ids:
        target_findings = [
            f for f in context.findings
            if f.target_id == target_id and f.status == "open"
        ]
        category_counts: Counter[str] = Counter(
            f.attack_category for f in target_findings
        )
        persistent = [cat for cat, count in category_counts.items() if count >= 3]
        if not persistent:
            continue
        finding_ids = tuple(
            f.finding_id for f in target_findings
            if f.attack_category in persistent
        )
        categories_str = ", ".join(persistent[:3])
        insight, _ = SecurityInsight.create(
            organization_id=context.organization_id,
            insight_type=InsightType.PATTERN,
            title=f"Persistent Attack Vector: {categories_str}",
            description=(
                f"Target {target_id!r} has open findings for {categories_str} "
                f"across {category_counts[persistent[0]]}+ validation runs. "
                f"This attack vector is not being remediated."
            ),
            affected_targets=(target_id,),
            supporting_finding_ids=finding_ids[:20],
            confidence=0.85,
        )
        results.append(insight)
    return results


def _cross_target_vulnerability(context: IntelligenceContext) -> list[SecurityInsight]:
    """Detect: same attack category fails across >= 3 distinct targets."""
    category_to_targets: dict[str, set[str]] = {}
    for f in context.findings:
        if f.status == "open":
            category_to_targets.setdefault(f.attack_category, set()).add(f.target_id)

    results: list[SecurityInsight] = []
    for category, targets in category_to_targets.items():
        if len(targets) < 3:
            continue
        affected = tuple(sorted(targets))
        finding_ids = tuple(
            f.finding_id for f in context.findings
            if f.attack_category == category and f.target_id in targets
        )[:20]
        insight, _ = SecurityInsight.create(
            organization_id=context.organization_id,
            insight_type=InsightType.CORRELATION,
            title=f"Cross-Target Vulnerability: {category}",
            description=(
                f"Attack category {category!r} produces open findings on "
                f"{len(targets)} targets. This is a systemic vulnerability "
                f"affecting the entire AI inventory, not isolated to one target."
            ),
            affected_targets=affected,
            supporting_finding_ids=finding_ids,
            confidence=0.90,
        )
        results.append(insight)
    return results


def _security_degradation_trend(context: IntelligenceContext) -> list[SecurityInsight]:
    """Detect: vulnerability rate increasing over last 3+ snapshots per target."""
    results: list[SecurityInsight] = []
    for target_id in context.target_ids:
        snaps = sorted(
            (s for s in context.snapshots if s.target_id == target_id),
            key=lambda s: s.created_at_iso or "",
        )
        if len(snaps) < 3:
            continue
        rates = [s.vulnerability_rate for s in snaps[-5:]]
        if _is_monotone_increasing(rates, tolerance=0.02):
            delta = rates[-1] - rates[0]
            insight, _ = SecurityInsight.create(
                organization_id=context.organization_id,
                insight_type=InsightType.TREND,
                title=f"Security Degradation Trend on Target {target_id[:12]}",
                description=(
                    f"Target {target_id!r} shows a consistent increase in vulnerability "
                    f"rate over the last {len(rates)} snapshots "
                    f"(+{delta:.1%}). Immediate investigation required."
                ),
                affected_targets=(target_id,),
                supporting_finding_ids=(),
                confidence=0.80,
            )
            results.append(insight)
    return results


def _regression_after_stable(context: IntelligenceContext) -> list[SecurityInsight]:
    """Detect: target whose vulnerability rate jumped significantly vs. its own history."""
    results: list[SecurityInsight] = []
    for target_id in context.target_ids:
        snaps = sorted(
            (s for s in context.snapshots if s.target_id == target_id),
            key=lambda s: s.created_at_iso or "",
        )
        if len(snaps) < 4:
            continue
        historic = snaps[:-1]
        latest = snaps[-1]
        hist_rates = [s.vulnerability_rate for s in historic]
        hist_mean = sum(hist_rates) / len(hist_rates)
        if latest.vulnerability_rate - hist_mean >= 0.15:
            insight, _ = SecurityInsight.create(
                organization_id=context.organization_id,
                insight_type=InsightType.REGRESSION,
                title=f"Unexplained Security Regression on Target {target_id[:12]}",
                description=(
                    f"Target {target_id!r} vulnerability rate jumped from "
                    f"historical mean {hist_mean:.1%} to {latest.vulnerability_rate:.1%} "
                    f"in the most recent validation — a delta of "
                    f"+{latest.vulnerability_rate - hist_mean:.1%}."
                ),
                affected_targets=(target_id,),
                confidence=0.75,
            )
            results.append(insight)
    return results


def _drift_coincides_with_regression(context: IntelligenceContext) -> list[SecurityInsight]:
    """Detect: a significant drift event closely precedes a regression."""
    results: list[SecurityInsight] = []
    significant_drifts = {d.target_snapshot_id for d in context.drift_events if d.is_significant}
    if not significant_drifts:
        return []

    for target_id in context.target_ids:
        snaps = sorted(
            (s for s in context.snapshots if s.target_id == target_id),
            key=lambda s: s.created_at_iso or "",
        )
        if len(snaps) < 2:
            continue
        # Look for pairs where the earlier snap is a drift target and rate worsened
        for i in range(len(snaps) - 1):
            prev = snaps[i]
            curr = snaps[i + 1]
            if prev.snapshot_id in significant_drifts:
                delta = curr.vulnerability_rate - prev.vulnerability_rate
                if delta >= 0.10:
                    insight, _ = SecurityInsight.create(
                        organization_id=context.organization_id,
                        insight_type=InsightType.ANOMALY,
                        title=f"Drift-Induced Regression on Target {target_id[:12]}",
                        description=(
                            f"A significant configuration change (model/provider/prompt) "
                            f"on target {target_id!r} was followed by a "
                            f"{delta:.1%} increase in vulnerability rate. "
                            f"The configuration change may have introduced new vulnerabilities."
                        ),
                        affected_targets=(target_id,),
                        confidence=0.85,
                    )
                    results.append(insight)
                    break
    return results


def _stale_critical_finding(context: IntelligenceContext) -> list[SecurityInsight]:
    """Detect: critical-severity findings open for > 7 days."""
    import contextlib
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    stale_threshold_days = 7
    stale_findings: list[FindingInput] = []

    for f in context.findings:
        if f.severity != "critical" or f.status != "open" or not f.created_at_iso:
            continue
        with contextlib.suppress(Exception):
            dt = datetime.fromisoformat(f.created_at_iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if (now - dt).days >= stale_threshold_days:
                stale_findings.append(f)

    if not stale_findings:
        return []

    affected = tuple({f.target_id for f in stale_findings})
    finding_ids = tuple(f.finding_id for f in stale_findings[:20])
    insight, _ = SecurityInsight.create(
        organization_id=context.organization_id,
        insight_type=InsightType.ANOMALY,
        title=f"{len(stale_findings)} Critical Finding(s) Unresolved > {stale_threshold_days} Days",
        description=(
            f"{len(stale_findings)} critical-severity finding(s) have been open "
            f"for more than {stale_threshold_days} days without remediation. "
            f"Affected targets: {', '.join(affected[:3])}"
            + (" and more" if len(affected) > 3 else "")
            + "."
        ),
        affected_targets=affected,
        supporting_finding_ids=finding_ids,
        confidence=0.95,
    )
    return [insight]


def _is_monotone_increasing(values: list[float], tolerance: float = 0.02) -> bool:
    """True if each value is at least (prev - tolerance) in a list."""
    if len(values) < 2:
        return False
    for i in range(1, len(values)):
        if values[i] < values[i - 1] - tolerance:
            return False
    return values[-1] > values[0] + tolerance

"""Unit tests for Risk Correlation Engine.

Covers: value objects, scoring, factor extraction, incident production,
priority assignment, trend detection, history, large datasets,
repeated attacks, mixed severity, algorithm replacement, and regression.
"""

from datetime import UTC, datetime, timedelta

import pytest

from redforge.application.risk_engine import (
    DefaultRiskScoreCalculator,
    EvidenceChainInput,
    FindingInput,
    IncidentStatus,
    RiskCorrelationEngine,
    RiskFactor,
    RiskFactorExtractor,
    RiskFactorType,
    RiskHistory,
    RiskPriority,
    RiskScore,
    RiskScoreCalculator,
    RiskTrend,
    ValidationResultInput,
)

# ─── Factories ────────────────────────────────────────────────────────────────


def _finding(
    finding_id: str = "f-1",
    target_id: str = "t-1",
    organization_id: str = "org-1",
    run_id: str = "run-1",
    severity: str = "high",
    risk_score: float = 7.5,
    title: str = "Prompt injection vulnerability",
    evidence_ids: list[str] | None = None,
    attack_type: str = "prompt_injection",
    provider: str = "openai",
    model: str = "gpt-4",
) -> FindingInput:
    return FindingInput(
        finding_id=finding_id,
        target_id=target_id,
        organization_id=organization_id,
        run_id=run_id,
        severity=severity,
        risk_score=risk_score,
        title=title,
        evidence_ids=evidence_ids or ["e-1", "e-2"],
        attack_type=attack_type,
        provider=provider,
        model=model,
    )


def _chain(
    chain_id: str = "chain-1",
    evidence_ids: list[str] | None = None,
    attack_ids: list[str] | None = None,
    run_id: str = "run-1",
    target_id: str = "t-1",
    correlation_score: float = 0.85,
    summary: str = "Multi-step injection chain",
    minutes_offset: int = 0,
) -> EvidenceChainInput:
    base = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
    return EvidenceChainInput(
        chain_id=chain_id,
        evidence_ids=evidence_ids or ["e-1", "e-2", "e-3"],
        attack_ids=attack_ids or ["a-1", "a-2"],
        run_id=run_id,
        target_id=target_id,
        correlation_score=correlation_score,
        summary=summary,
        timeline_start=base + timedelta(minutes=minutes_offset),
        timeline_end=base + timedelta(minutes=minutes_offset + 5),
    )


def _validation(
    run_id: str = "run-1",
    target_id: str = "t-1",
    organization_id: str = "org-1",
    status: str = "completed",
    total_checks: int = 50,
    failed_checks: int = 10,
    passed_checks: int = 40,
    duration_ms: int = 5000,
) -> ValidationResultInput:
    return ValidationResultInput(
        run_id=run_id,
        target_id=target_id,
        organization_id=organization_id,
        status=status,
        total_checks=total_checks,
        failed_checks=failed_checks,
        passed_checks=passed_checks,
        duration_ms=duration_ms,
    )


# ─── Value Object Tests ───────────────────────────────────────────────────────


class TestRiskFactor:
    def test_valid_creation(self) -> None:
        f = RiskFactor(
            factor_type=RiskFactorType.LIKELIHOOD,
            score=0.8,
            weight=0.9,
            rationale="High failure rate",
        )
        assert f.score == 0.8
        assert f.weight == 0.9
        assert f.weighted_score == pytest.approx(0.72)

    def test_score_below_zero_raises(self) -> None:
        with pytest.raises(ValueError, match=r"0\.0-1\.0"):
            RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=-0.1,
                weight=0.5,
                rationale="invalid",
            )

    def test_score_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match=r"0\.0-1\.0"):
            RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=1.1,
                weight=0.5,
                rationale="invalid",
            )

    def test_weight_below_zero_raises(self) -> None:
        with pytest.raises(ValueError, match=r"0\.0-1\.0"):
            RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=0.5,
                weight=-0.1,
                rationale="invalid",
            )

    def test_weight_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match=r"0\.0-1\.0"):
            RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=0.5,
                weight=1.1,
                rationale="invalid",
            )

    def test_zero_weight_gives_zero_weighted_score(self) -> None:
        f = RiskFactor(
            factor_type=RiskFactorType.CONFIDENCE,
            score=1.0,
            weight=0.0,
            rationale="zero weight",
        )
        assert f.weighted_score == 0.0


class TestRiskScore:
    def test_valid_creation(self) -> None:
        s = RiskScore(overall=7.5, factors=())
        assert s.overall == 7.5
        assert s.priority == RiskPriority.HIGH

    def test_critical_priority(self) -> None:
        assert RiskScore(overall=9.5, factors=()).priority == RiskPriority.CRITICAL

    def test_medium_priority(self) -> None:
        assert RiskScore(overall=5.0, factors=()).priority == RiskPriority.MEDIUM

    def test_low_priority(self) -> None:
        assert RiskScore(overall=2.0, factors=()).priority == RiskPriority.LOW

    def test_informational_priority(self) -> None:
        assert RiskScore(overall=0.5, factors=()).priority == RiskPriority.INFORMATIONAL

    def test_below_zero_raises(self) -> None:
        with pytest.raises(ValueError, match=r"0\.0-10\.0"):
            RiskScore(overall=-1.0, factors=())

    def test_above_ten_raises(self) -> None:
        with pytest.raises(ValueError, match=r"0\.0-10\.0"):
            RiskScore(overall=10.1, factors=())


class TestRiskHistory:
    def test_empty_history_trend_is_new(self) -> None:
        h = RiskHistory()
        assert h.trend() == RiskTrend.NEW

    def test_single_entry_trend_is_new(self) -> None:
        h = RiskHistory()
        h.add(7.0, RiskPriority.HIGH, "created")
        assert h.trend() == RiskTrend.NEW

    def test_increasing_trend(self) -> None:
        h = RiskHistory()
        h.add(3.0, RiskPriority.LOW, "initial")
        h.add(7.0, RiskPriority.HIGH, "escalated")
        assert h.trend() == RiskTrend.INCREASING

    def test_decreasing_trend(self) -> None:
        h = RiskHistory()
        h.add(8.0, RiskPriority.HIGH, "initial")
        h.add(4.0, RiskPriority.MEDIUM, "mitigated")
        assert h.trend() == RiskTrend.DECREASING

    def test_stable_trend(self) -> None:
        h = RiskHistory()
        h.add(5.0, RiskPriority.MEDIUM, "initial")
        h.add(5.2, RiskPriority.MEDIUM, "stable")
        assert h.trend() == RiskTrend.STABLE

    def test_latest_score(self) -> None:
        h = RiskHistory()
        h.add(3.0, RiskPriority.LOW, "a")
        h.add(7.0, RiskPriority.HIGH, "b")
        assert h.latest_score == 7.0

    def test_empty_latest_score(self) -> None:
        h = RiskHistory()
        assert h.latest_score == 0.0


# ─── Score Calculator Tests ───────────────────────────────────────────────────


class TestDefaultRiskScoreCalculator:
    def test_empty_factors(self) -> None:
        calc = DefaultRiskScoreCalculator()
        score = calc.calculate([])
        assert score.overall == 0.0
        assert score.factors == ()

    def test_single_factor(self) -> None:
        calc = DefaultRiskScoreCalculator()
        factors = [
            RiskFactor(
                factor_type=RiskFactorType.IMPACT,
                score=0.8,
                weight=1.0,
                rationale="high impact",
            )
        ]
        score = calc.calculate(factors)
        assert score.overall == 8.0

    def test_multiple_factors_weighted(self) -> None:
        calc = DefaultRiskScoreCalculator()
        factors = [
            RiskFactor(RiskFactorType.IMPACT, score=1.0, weight=1.0, rationale="max"),
            RiskFactor(RiskFactorType.LIKELIHOOD, score=0.5, weight=0.5, rationale="mid"),
        ]
        score = calc.calculate(factors)
        # weighted_sum = 1.0*1.0 + 0.5*0.5 = 1.25
        # total_weight = 1.0 + 0.5 = 1.5
        # raw = (1.25/1.5) * 10 = 8.33
        assert score.overall == pytest.approx(8.33, abs=0.01)

    def test_zero_weight_factors(self) -> None:
        calc = DefaultRiskScoreCalculator()
        factors = [
            RiskFactor(RiskFactorType.IMPACT, score=1.0, weight=0.0, rationale="zero"),
        ]
        score = calc.calculate(factors)
        # total_weight = 0, returns 0.0
        assert score.overall == 0.0

    def test_all_max_factors_cap_at_ten(self) -> None:
        calc = DefaultRiskScoreCalculator()
        factors = [
            RiskFactor(RiskFactorType.IMPACT, score=1.0, weight=1.0, rationale="max"),
            RiskFactor(RiskFactorType.LIKELIHOOD, score=1.0, weight=1.0, rationale="max"),
            RiskFactor(RiskFactorType.EXPLOITABILITY, score=1.0, weight=1.0, rationale="max"),
        ]
        score = calc.calculate(factors)
        assert score.overall == 10.0

    def test_satisfies_protocol(self) -> None:
        calc = DefaultRiskScoreCalculator()
        assert isinstance(calc, RiskScoreCalculator)


# ─── Factor Extractor Tests ───────────────────────────────────────────────────


class TestRiskFactorExtractor:
    def test_extracts_all_factor_types(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [_finding()]
        chains = [_chain()]
        validations = [_validation()]
        factors = extractor.extract(findings, chains, validations)
        types = {f.factor_type for f in factors}
        assert RiskFactorType.LIKELIHOOD in types
        assert RiskFactorType.IMPACT in types
        assert RiskFactorType.EXPLOITABILITY in types
        assert RiskFactorType.BUSINESS_CRITICALITY in types
        assert RiskFactorType.CONFIDENCE in types
        assert RiskFactorType.EVIDENCE_STRENGTH in types
        assert RiskFactorType.REPEATED_OCCURRENCE in types
        assert RiskFactorType.CROSS_VALIDATION in types
        assert RiskFactorType.REPEATED_TARGET in types
        assert RiskFactorType.PROVIDER_RISK in types
        assert RiskFactorType.MODEL_SENSITIVITY in types
        assert len(factors) == 11

    def test_empty_inputs(self) -> None:
        extractor = RiskFactorExtractor()
        factors = extractor.extract([], [], [])
        assert len(factors) == 11
        # Core factors should have score 0.0 for empty inputs
        core_types = {
            RiskFactorType.LIKELIHOOD,
            RiskFactorType.IMPACT,
            RiskFactorType.EVIDENCE_STRENGTH,
            RiskFactorType.REPEATED_OCCURRENCE,
            RiskFactorType.REPEATED_TARGET,
        }
        for f in factors:
            if f.factor_type in core_types:
                assert f.score == 0.0, f"{f.factor_type} should be 0.0"

    def test_likelihood_from_validation(self) -> None:
        extractor = RiskFactorExtractor()
        validations = [_validation(total_checks=100, failed_checks=50, passed_checks=50)]
        factors = extractor.extract([_finding()], [], validations)
        likelihood = next(f for f in factors if f.factor_type == RiskFactorType.LIKELIHOOD)
        # 50/100 = 0.5 * 1.2 = 0.6
        assert likelihood.score == pytest.approx(0.6, abs=0.01)

    def test_impact_biased_toward_max_severity(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [
            _finding(finding_id="f1", severity="critical"),
            _finding(finding_id="f2", severity="low"),
        ]
        factors = extractor.extract(findings, [], [])
        impact = next(f for f in factors if f.factor_type == RiskFactorType.IMPACT)
        # max=1.0, avg=(1.0+0.3)/2=0.65, combined=0.7*1.0+0.3*0.65=0.895
        assert impact.score >= 0.8

    def test_exploitability_with_chains(self) -> None:
        extractor = RiskFactorExtractor()
        chains = [_chain(correlation_score=0.9, evidence_ids=["e1", "e2", "e3", "e4"])]
        factors = extractor.extract([_finding()], chains, [])
        expl = next(f for f in factors if f.factor_type == RiskFactorType.EXPLOITABILITY)
        assert expl.score > 0.3  # Higher than "no chains" baseline

    def test_exploitability_without_chains(self) -> None:
        extractor = RiskFactorExtractor()
        factors = extractor.extract([_finding()], [], [])
        expl = next(f for f in factors if f.factor_type == RiskFactorType.EXPLOITABILITY)
        assert expl.score == 0.3

    def test_repeated_occurrence_amplification(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [
            _finding(finding_id=f"f{i}", attack_type="prompt_injection")
            for i in range(6)
        ]
        factors = extractor.extract(findings, [], [])
        repeated = next(
            f for f in factors if f.factor_type == RiskFactorType.REPEATED_OCCURRENCE
        )
        # 6 findings of same type: (6-1)*0.2 = 1.0 (capped)
        assert repeated.score == 1.0

    def test_cross_validation_amplification(self) -> None:
        extractor = RiskFactorExtractor()
        chains = [
            _chain(chain_id="c1", run_id="run-1"),
            _chain(chain_id="c2", run_id="run-2"),
            _chain(chain_id="c3", run_id="run-3"),
        ]
        validations = [_validation(run_id="run-4")]
        factors = extractor.extract([_finding()], chains, validations)
        cross = next(f for f in factors if f.factor_type == RiskFactorType.CROSS_VALIDATION)
        # 4 unique runs: (4-1)*0.25 = 0.75
        assert cross.score == pytest.approx(0.75, abs=0.01)

    def test_repeated_target_amplification(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [
            _finding(finding_id=f"f{i}", target_id="t-1") for i in range(5)
        ]
        factors = extractor.extract(findings, [], [])
        target_factor = next(
            f for f in factors if f.factor_type == RiskFactorType.REPEATED_TARGET
        )
        # 5 hits on same target: (5-1)*0.15 = 0.6
        assert target_factor.score == pytest.approx(0.6, abs=0.01)

    def test_provider_risk_openai(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [_finding(provider="openai")]
        factors = extractor.extract(findings, [], [])
        provider = next(f for f in factors if f.factor_type == RiskFactorType.PROVIDER_RISK)
        assert provider.score == 0.7

    def test_provider_risk_custom(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [_finding(provider="custom")]
        factors = extractor.extract(findings, [], [])
        provider = next(f for f in factors if f.factor_type == RiskFactorType.PROVIDER_RISK)
        assert provider.score == 0.8

    def test_model_sensitivity_high(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [_finding(model="gpt-4-turbo")]
        factors = extractor.extract(findings, [], [])
        model = next(f for f in factors if f.factor_type == RiskFactorType.MODEL_SENSITIVITY)
        assert model.score == 0.8

    def test_model_sensitivity_lower(self) -> None:
        extractor = RiskFactorExtractor()
        findings = [_finding(model="llama-2-7b")]
        factors = extractor.extract(findings, [], [])
        model = next(f for f in factors if f.factor_type == RiskFactorType.MODEL_SENSITIVITY)
        assert model.score == 0.4


# ─── Risk Correlation Engine Tests ────────────────────────────────────────────


class TestRiskCorrelationEngine:
    def test_empty_findings_returns_empty(self) -> None:
        engine = RiskCorrelationEngine()
        incidents = engine.correlate([], [], [])
        assert incidents == []

    def test_single_finding_produces_incident(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding()]
        incidents = engine.correlate(findings)
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.organization_id == "org-1"
        assert inc.affected_targets == ["t-1"]
        assert inc.finding_ids == ["f-1"]
        assert inc.status == IncidentStatus.OPEN
        assert inc.trend == RiskTrend.NEW

    def test_incident_has_executive_summary(self) -> None:
        engine = RiskCorrelationEngine()
        incidents = engine.correlate([_finding()])
        assert incidents[0].executive_summary != ""
        assert "Risk Score" in incidents[0].executive_summary

    def test_incident_has_recommended_actions(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding(attack_type="prompt_injection", severity="critical")]
        incidents = engine.correlate(findings)
        actions = incidents[0].recommended_actions
        assert len(actions) >= 1
        assert any("prompt" in a.lower() or "input" in a.lower() for a in actions)

    def test_groups_by_target(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", target_id="t-1"),
            _finding(finding_id="f2", target_id="t-1"),
            _finding(finding_id="f3", target_id="t-2"),
        ]
        incidents = engine.correlate(findings)
        assert len(incidents) == 2
        targets = {inc.affected_targets[0] for inc in incidents}
        assert targets == {"t-1", "t-2"}

    def test_sorted_by_risk_score_descending(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", target_id="t-1", severity="low"),
            _finding(finding_id="f2", target_id="t-2", severity="critical"),
        ]
        incidents = engine.correlate(findings)
        assert incidents[0].risk_score.overall >= incidents[1].risk_score.overall

    def test_chains_amplify_score(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding()]
        score_without_chains = engine.correlate(findings)[0].risk_score.overall

        engine2 = RiskCorrelationEngine()
        chains = [_chain(correlation_score=0.95)]
        score_with_chains = engine2.correlate(findings, chains)[0].risk_score.overall

        assert score_with_chains >= score_without_chains

    def test_validations_affect_likelihood(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding()]

        # High failure rate
        high_fail = [_validation(total_checks=100, failed_checks=80, passed_checks=20)]
        score_high = engine.correlate(findings, validations=high_fail)[0].risk_score.overall

        engine2 = RiskCorrelationEngine()
        # Low failure rate
        low_fail = [_validation(total_checks=100, failed_checks=5, passed_checks=95)]
        score_low = engine2.correlate(findings, validations=low_fail)[0].risk_score.overall

        assert score_high > score_low

    def test_incident_contains_attack_types(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", attack_type="prompt_injection"),
            _finding(finding_id="f2", attack_type="data_exfiltration"),
        ]
        incidents = engine.correlate(findings)
        assert "prompt_injection" in incidents[0].attack_types
        assert "data_exfiltration" in incidents[0].attack_types

    def test_incident_has_history(self) -> None:
        engine = RiskCorrelationEngine()
        incidents = engine.correlate([_finding()])
        assert len(incidents[0].history.entries) == 1
        assert incidents[0].history.entries[0].event == "Incident created"

    def test_incident_title_includes_attack_type(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding(attack_type="jailbreak")]
        incidents = engine.correlate(findings)
        assert "Jailbreak" in incidents[0].title


class TestMergeIncidents:
    def test_merge_empty_returns_none(self) -> None:
        engine = RiskCorrelationEngine()
        assert engine.merge_incidents([]) is None

    def test_merge_single_returns_same(self) -> None:
        engine = RiskCorrelationEngine()
        incidents = engine.correlate([_finding()])
        merged = engine.merge_incidents(incidents)
        assert merged is not None
        assert merged.incident_id == incidents[0].incident_id

    def test_merge_multiple_combines_data(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", target_id="t-1"),
            _finding(finding_id="f2", target_id="t-2"),
        ]
        incidents = engine.correlate(findings)
        assert len(incidents) == 2

        merged = engine.merge_incidents(incidents)
        assert merged is not None
        assert "f1" in merged.finding_ids
        assert "f2" in merged.finding_ids
        assert set(merged.affected_targets) == {"t-1", "t-2"}
        assert "MERGED" in merged.incident_id

    def test_merge_recalculates_score(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", target_id="t-1", severity="critical"),
            _finding(finding_id="f2", target_id="t-2", severity="low"),
        ]
        incidents = engine.correlate(findings)
        merged = engine.merge_incidents(incidents)
        assert merged is not None
        # Merged score should use best factors from each
        assert merged.risk_score.overall > 0


# ─── Custom Calculator (Algorithm Replacement) ───────────────────────────────


class FixedScoreCalculator:
    """Test calculator that always returns a fixed score."""

    def __init__(self, fixed: float = 5.0) -> None:
        self._fixed = fixed

    def calculate(self, factors: list[RiskFactor]) -> RiskScore:
        return RiskScore(overall=self._fixed, factors=tuple(factors))


class TestCustomCalculator:
    def test_engine_uses_injected_calculator(self) -> None:
        calc = FixedScoreCalculator(fixed=3.0)
        engine = RiskCorrelationEngine(calculator=calc)
        incidents = engine.correlate([_finding()])
        assert incidents[0].risk_score.overall == 3.0

    def test_custom_calculator_satisfies_protocol(self) -> None:
        calc = FixedScoreCalculator()
        assert isinstance(calc, RiskScoreCalculator)

    def test_scoring_evolves_independently(self) -> None:
        """Verify the engine produces different results with different calculators."""
        engine_low = RiskCorrelationEngine(calculator=FixedScoreCalculator(2.0))
        engine_high = RiskCorrelationEngine(calculator=FixedScoreCalculator(9.0))

        findings = [_finding()]
        low_score = engine_low.correlate(findings)[0].risk_score.overall
        high_score = engine_high.correlate(findings)[0].risk_score.overall

        assert low_score == 2.0
        assert high_score == 9.0
        assert low_score != high_score


# ─── Large Dataset & Performance Tests ────────────────────────────────────────


class TestLargeDataset:
    def test_100_findings_across_targets(self) -> None:
        """100 findings across 10 targets should produce 10 incidents."""
        engine = RiskCorrelationEngine()
        findings = [
            _finding(
                finding_id=f"f-{i}",
                target_id=f"t-{i % 10}",
                severity=["critical", "high", "medium", "low"][i % 4],
                attack_type=f"attack-{i % 5}",
            )
            for i in range(100)
        ]
        incidents = engine.correlate(findings)
        assert len(incidents) == 10
        assert all(inc.finding_count == 10 for inc in incidents)

    def test_500_findings_completes(self) -> None:
        """Performance: 500 findings should correlate without timeout."""
        engine = RiskCorrelationEngine()
        findings = [
            _finding(
                finding_id=f"f-{i}",
                target_id=f"t-{i % 20}",
                run_id=f"run-{i % 5}",
                severity=["critical", "high", "medium", "low", "informational"][i % 5],
                attack_type=f"type-{i % 7}",
                provider=["openai", "anthropic", "google"][i % 3],
                model=["gpt-4", "claude-3", "gemini"][i % 3],
            )
            for i in range(500)
        ]
        chains = [
            _chain(
                chain_id=f"chain-{i}",
                target_id=f"t-{i % 20}",
                run_id=f"run-{i % 5}",
                correlation_score=0.7 + (i % 3) * 0.1,
            )
            for i in range(50)
        ]
        validations = [
            _validation(
                run_id=f"run-{i}",
                target_id=f"t-{i % 20}",
                total_checks=100,
                failed_checks=20 + i * 3,
                passed_checks=80 - i * 3,
            )
            for i in range(5)
        ]
        incidents = engine.correlate(findings, chains, validations)
        assert len(incidents) == 20
        # All scores should be valid
        assert all(0.0 <= inc.risk_score.overall <= 10.0 for inc in incidents)


# ─── Repeated Attack Tests ────────────────────────────────────────────────────


class TestRepeatedAttacks:
    def test_repeated_injection_amplifies_score(self) -> None:
        """Same attack type repeated should yield higher risk."""
        engine = RiskCorrelationEngine()
        single = engine.correlate([_finding(attack_type="prompt_injection")])

        engine2 = RiskCorrelationEngine()
        repeated = engine2.correlate([
            _finding(finding_id=f"f{i}", attack_type="prompt_injection")
            for i in range(10)
        ])

        assert repeated[0].risk_score.overall >= single[0].risk_score.overall

    def test_repeated_on_same_target_amplifies(self) -> None:
        """Multiple findings on same target should amplify target risk."""
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id=f"f{i}", target_id="t-1") for i in range(8)
        ]
        incidents = engine.correlate(findings)
        factors = incidents[0].risk_score.factors
        target_factor = next(
            f for f in factors if f.factor_type == RiskFactorType.REPEATED_TARGET
        )
        # (8-1)*0.15 = 1.05 → capped at 1.0
        assert target_factor.score == 1.0


# ─── Mixed Severity Tests ─────────────────────────────────────────────────────


class TestMixedSeverity:
    def test_critical_dominates_mixed(self) -> None:
        """Mix of severities should bias toward critical."""
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", severity="critical"),
            _finding(finding_id="f2", severity="informational"),
            _finding(finding_id="f3", severity="low"),
        ]
        incidents = engine.correlate(findings)
        # Impact factor should reflect the critical finding
        impact = next(
            f for f in incidents[0].risk_score.factors
            if f.factor_type == RiskFactorType.IMPACT
        )
        assert impact.score >= 0.8

    def test_all_informational_low_score(self) -> None:
        """All informational findings should yield low risk."""
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id=f"f{i}", severity="informational", provider="", model="")
            for i in range(5)
        ]
        incidents = engine.correlate(findings)
        assert incidents[0].risk_score.overall < 5.0

    def test_all_critical_high_score(self) -> None:
        """All critical findings should yield elevated risk."""
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id=f"f{i}", severity="critical") for i in range(5)
        ]
        incidents = engine.correlate(findings)
        assert incidents[0].risk_score.overall >= 6.0


# ─── Regression Tests ─────────────────────────────────────────────────────────


class TestRegression:
    def test_no_findings_no_crash(self) -> None:
        engine = RiskCorrelationEngine()
        assert engine.correlate([]) == []

    def test_findings_without_chains_or_validations(self) -> None:
        engine = RiskCorrelationEngine()
        incidents = engine.correlate([_finding()])
        assert len(incidents) == 1
        assert incidents[0].risk_score.overall > 0

    def test_findings_with_empty_attack_type(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding(attack_type="")]
        incidents = engine.correlate(findings)
        assert len(incidents) == 1

    def test_findings_with_empty_provider_and_model(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [_finding(provider="", model="")]
        incidents = engine.correlate(findings)
        assert len(incidents) == 1

    def test_priority_matches_score(self) -> None:
        """Incident priority must match score.priority."""
        engine = RiskCorrelationEngine()
        findings = [_finding(severity="critical")]
        incidents = engine.correlate(findings)
        inc = incidents[0]
        assert inc.priority == inc.risk_score.priority

    def test_incident_id_is_unique(self) -> None:
        engine = RiskCorrelationEngine()
        findings = [
            _finding(finding_id="f1", target_id="t-1"),
            _finding(finding_id="f2", target_id="t-2"),
        ]
        incidents = engine.correlate(findings)
        ids = [inc.incident_id for inc in incidents]
        assert len(ids) == len(set(ids))

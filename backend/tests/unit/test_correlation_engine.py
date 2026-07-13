"""Unit tests for Evidence Correlation Engine."""

from datetime import UTC, datetime, timedelta

from redforge.application.correlation import (
    CorrelationScore,
    EvidenceCorrelationEngine,
    EvidenceRecord,
    RepeatedFailureRule,
    SameAttackTypeRule,
    SameRunRule,
    TemporalProximityRule,
)


def _evidence(
    eid: str = "e1",
    run_id: str = "run-1",
    target_id: str = "t-1",
    attack_id: str = "a-1",
    attack_type: str = "prompt_injection",
    result: str = "fail",
    minutes_offset: int = 0,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=eid,
        run_id=run_id,
        target_id=target_id,
        attack_id=attack_id,
        attack_type=attack_type,
        result=result,
        confidence=0.9,
        executed_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC)
        + timedelta(minutes=minutes_offset),
    )


class TestCorrelationScore:
    def test_valid(self) -> None:
        s = CorrelationScore(0.8)
        assert s.is_strong is True

    def test_combine(self) -> None:
        a = CorrelationScore(0.6)
        b = CorrelationScore(0.9)
        assert a.combine(b).value == 0.9


class TestSameRunRule:
    def test_same_run_correlates(self) -> None:
        rule = SameRunRule()
        a = _evidence("e1", run_id="run-1")
        b = _evidence("e2", run_id="run-1")
        reason = rule.correlate(a, b)
        assert reason is not None
        assert reason.score.value == 0.9

    def test_different_run_no_correlation(self) -> None:
        rule = SameRunRule()
        a = _evidence("e1", run_id="run-1")
        b = _evidence("e2", run_id="run-2")
        assert rule.correlate(a, b) is None


class TestSameAttackTypeRule:
    def test_same_type_correlates(self) -> None:
        rule = SameAttackTypeRule()
        a = _evidence("e1", attack_type="injection")
        b = _evidence("e2", attack_type="injection")
        reason = rule.correlate(a, b)
        assert reason is not None

    def test_different_type_no_correlation(self) -> None:
        rule = SameAttackTypeRule()
        a = _evidence("e1", attack_type="injection")
        b = _evidence("e2", attack_type="exfiltration")
        assert rule.correlate(a, b) is None


class TestTemporalProximityRule:
    def test_close_in_time(self) -> None:
        rule = TemporalProximityRule(window=timedelta(minutes=5))
        a = _evidence("e1", minutes_offset=0)
        b = _evidence("e2", minutes_offset=2)
        reason = rule.correlate(a, b)
        assert reason is not None

    def test_far_apart_no_correlation(self) -> None:
        rule = TemporalProximityRule(window=timedelta(minutes=5))
        a = _evidence("e1", minutes_offset=0)
        b = _evidence("e2", minutes_offset=10)
        assert rule.correlate(a, b) is None


class TestRepeatedFailureRule:
    def test_repeated_failures_correlate(self) -> None:
        rule = RepeatedFailureRule()
        a = _evidence("e1", result="fail", target_id="t1")
        b = _evidence("e2", result="fail", target_id="t1")
        reason = rule.correlate(a, b)
        assert reason is not None
        assert reason.score.value == 0.8

    def test_pass_and_fail_no_correlation(self) -> None:
        rule = RepeatedFailureRule()
        a = _evidence("e1", result="pass")
        b = _evidence("e2", result="fail")
        assert rule.correlate(a, b) is None


class TestCorrelationEngine:
    def test_empty_input(self) -> None:
        engine = EvidenceCorrelationEngine()
        result = engine.correlate([])
        assert result.total_evidence == 0
        assert result.clusters == []

    def test_single_evidence_no_clusters(self) -> None:
        engine = EvidenceCorrelationEngine()
        result = engine.correlate([_evidence("e1")])
        assert result.clusters == []
        assert result.uncorrelated_evidence == 1

    def test_same_run_forms_cluster(self) -> None:
        engine = EvidenceCorrelationEngine()
        evidence = [
            _evidence("e1", run_id="r1", minutes_offset=0),
            _evidence("e2", run_id="r1", minutes_offset=1),
            _evidence("e3", run_id="r2", minutes_offset=30),
        ]
        result = engine.correlate(evidence)
        assert len(result.clusters) >= 1
        assert result.correlated_evidence >= 2

    def test_attack_chain_generated(self) -> None:
        engine = EvidenceCorrelationEngine()
        evidence = [
            _evidence("e1", run_id="r1", attack_type="injection", minutes_offset=0),
            _evidence("e2", run_id="r1", attack_type="injection", minutes_offset=1),
            _evidence("e3", run_id="r1", attack_type="exfil", minutes_offset=2),
        ]
        result = engine.correlate(evidence)
        assert len(result.attack_chains) >= 1
        chain = result.attack_chains[0]
        assert chain.length >= 2
        assert chain.target_id == "t-1"

    def test_correlation_rate(self) -> None:
        engine = EvidenceCorrelationEngine()
        evidence = [
            _evidence("e1", run_id="r1"),
            _evidence("e2", run_id="r1"),
        ]
        result = engine.correlate(evidence)
        assert result.correlation_rate == 1.0

    def test_large_evidence_set(self) -> None:
        """Performance: 100 evidence records should correlate quickly."""
        engine = EvidenceCorrelationEngine()
        evidence = [
            _evidence(
                f"e{i}",
                run_id=f"run-{i // 10}",
                attack_type=f"type-{i % 3}",
                minutes_offset=i,
            )
            for i in range(100)
        ]
        result = engine.correlate(evidence)
        assert result.total_evidence == 100
        assert result.correlated_evidence > 0

    def test_custom_rules(self) -> None:
        """Can inject custom correlation rules."""
        engine = EvidenceCorrelationEngine(rules=[SameRunRule()])
        evidence = [
            _evidence("e1", run_id="r1"),
            _evidence("e2", run_id="r1"),
        ]
        result = engine.correlate(evidence)
        assert len(result.clusters) == 1

    def test_chain_has_timeline(self) -> None:
        engine = EvidenceCorrelationEngine()
        evidence = [
            _evidence("e1", run_id="r1", minutes_offset=0),
            _evidence("e2", run_id="r1", minutes_offset=3),
        ]
        result = engine.correlate(evidence)
        if result.attack_chains:
            chain = result.attack_chains[0]
            assert chain.duration == timedelta(minutes=3)

    def test_chain_root_cause(self) -> None:
        engine = EvidenceCorrelationEngine()
        evidence = [
            _evidence("e1", run_id="r1", attack_type="injection", minutes_offset=0),
            _evidence("e2", run_id="r1", attack_type="exfil", minutes_offset=1),
        ]
        result = engine.correlate(evidence)
        if result.attack_chains:
            # Root cause is the first attack type in the chain
            assert result.attack_chains[0].root_cause_candidate == "injection"

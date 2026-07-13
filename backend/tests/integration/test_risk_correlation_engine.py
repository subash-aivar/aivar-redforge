"""Integration tests for Risk Correlation Engine.

Tests the full pipeline: evidence → correlation → risk incidents.
Validates end-to-end behavior with realistic data volumes and patterns.
"""

from datetime import UTC, datetime, timedelta

from redforge.application.correlation import (
    EvidenceCorrelationEngine,
    EvidenceRecord,
)
from redforge.application.risk_engine import (
    EvidenceChainInput,
    FindingInput,
    IncidentStatus,
    RiskCorrelationEngine,
    RiskFactorType,
    RiskPriority,
    RiskTrend,
    ValidationResultInput,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _evidence(
    eid: str,
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
        executed_at=datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        + timedelta(minutes=minutes_offset),
    )


def _finding_from_evidence(
    finding_id: str,
    evidence_ids: list[str],
    target_id: str = "t-1",
    severity: str = "high",
    attack_type: str = "prompt_injection",
    run_id: str = "run-1",
    provider: str = "openai",
    model: str = "gpt-4",
) -> FindingInput:
    return FindingInput(
        finding_id=finding_id,
        target_id=target_id,
        organization_id="org-1",
        run_id=run_id,
        severity=severity,
        risk_score=7.0,
        title=f"Finding: {attack_type}",
        evidence_ids=evidence_ids,
        attack_type=attack_type,
        provider=provider,
        model=model,
    )


# ─── Full Pipeline Tests ─────────────────────────────────────────────────────


class TestFullPipeline:
    """Tests evidence → correlation → risk incident production."""

    def test_evidence_to_risk_incidents(self) -> None:
        """Complete pipeline: evidence records → correlation → risk incidents."""
        # Step 1: Evidence records
        evidence = [
            _evidence("e1", attack_type="prompt_injection", minutes_offset=0),
            _evidence("e2", attack_type="prompt_injection", minutes_offset=1),
            _evidence("e3", attack_type="data_exfiltration", minutes_offset=3),
            _evidence("e4", attack_type="jailbreak", minutes_offset=5),
        ]

        # Step 2: Correlate evidence into chains
        correlation_engine = EvidenceCorrelationEngine()
        correlation_result = correlation_engine.correlate(evidence)

        # Step 3: Convert correlation output to risk engine inputs
        chains: list[EvidenceChainInput] = []
        for chain in correlation_result.attack_chains:
            chains.append(
                EvidenceChainInput(
                    chain_id=chain.chain_id,
                    evidence_ids=chain.evidence_ids,
                    attack_ids=chain.attack_ids,
                    run_id=chain.run_id,
                    target_id=chain.target_id,
                    correlation_score=chain.correlation_score.value,
                    summary=chain.summary,
                    timeline_start=chain.timeline_start,
                    timeline_end=chain.timeline_end,
                )
            )

        # Step 4: Create findings from evidence
        findings = [
            _finding_from_evidence("f1", ["e1", "e2"], attack_type="prompt_injection"),
            _finding_from_evidence("f2", ["e3"], attack_type="data_exfiltration"),
            _finding_from_evidence("f3", ["e4"], attack_type="jailbreak"),
        ]

        # Step 5: Validation results
        validations = [
            ValidationResultInput(
                run_id="run-1",
                target_id="t-1",
                organization_id="org-1",
                status="completed",
                total_checks=50,
                failed_checks=15,
                passed_checks=35,
                duration_ms=3000,
            )
        ]

        # Step 6: Produce risk incidents
        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings, chains, validations)

        # Assertions
        assert len(incidents) >= 1
        incident = incidents[0]
        assert incident.organization_id == "org-1"
        assert incident.status == IncidentStatus.OPEN
        assert incident.risk_score.overall > 0
        assert incident.executive_summary != ""
        assert len(incident.recommended_actions) >= 1
        assert "t-1" in incident.affected_targets
        assert incident.trend == RiskTrend.NEW

    def test_multi_target_pipeline(self) -> None:
        """Multiple targets produce separate incidents sorted by severity."""
        evidence = [
            # Target 1: critical injection attacks
            _evidence("e1", target_id="t-1", attack_type="prompt_injection"),
            _evidence("e2", target_id="t-1", attack_type="prompt_injection"),
            _evidence("e3", target_id="t-1", attack_type="jailbreak"),
            # Target 2: low severity
            _evidence("e4", target_id="t-2", attack_type="information_disclosure", result="fail"),
        ]

        correlation_engine = EvidenceCorrelationEngine()
        correlation_result = correlation_engine.correlate(evidence)

        chains = [
            EvidenceChainInput(
                chain_id=c.chain_id,
                evidence_ids=c.evidence_ids,
                attack_ids=c.attack_ids,
                run_id=c.run_id,
                target_id=c.target_id,
                correlation_score=c.correlation_score.value,
                summary=c.summary,
                timeline_start=c.timeline_start,
                timeline_end=c.timeline_end,
            )
            for c in correlation_result.attack_chains
        ]

        findings = [
            _finding_from_evidence(
                "f1", ["e1", "e2"], target_id="t-1",
                severity="critical", attack_type="prompt_injection",
            ),
            _finding_from_evidence(
                "f2", ["e3"], target_id="t-1",
                severity="high", attack_type="jailbreak",
            ),
            _finding_from_evidence(
                "f3", ["e4"], target_id="t-2",
                severity="low", attack_type="information_disclosure",
            ),
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings, chains)

        assert len(incidents) == 2
        # Higher severity target should be first
        assert incidents[0].affected_targets == ["t-1"]
        assert incidents[0].risk_score.overall > incidents[1].risk_score.overall


class TestLargeDatasetIntegration:
    """Integration tests with large realistic data volumes."""

    def test_200_evidence_full_pipeline(self) -> None:
        """200 evidence records through full pipeline."""
        # Generate evidence
        evidence = [
            _evidence(
                f"e-{i}",
                run_id=f"run-{i // 20}",
                target_id=f"t-{i % 5}",
                attack_type=["prompt_injection", "jailbreak", "data_exfiltration",
                             "model_abuse", "denial_of_service"][i % 5],
                result="fail" if i % 3 != 0 else "pass",
                minutes_offset=i,
            )
            for i in range(200)
        ]

        # Correlate
        correlation_engine = EvidenceCorrelationEngine()
        correlation_result = correlation_engine.correlate(evidence)

        # Convert chains
        chains = [
            EvidenceChainInput(
                chain_id=c.chain_id,
                evidence_ids=c.evidence_ids,
                attack_ids=c.attack_ids,
                run_id=c.run_id,
                target_id=c.target_id,
                correlation_score=c.correlation_score.value,
                summary=c.summary,
                timeline_start=c.timeline_start,
                timeline_end=c.timeline_end,
            )
            for c in correlation_result.attack_chains
        ]

        # Create findings (one per failing evidence)
        findings = [
            _finding_from_evidence(
                f"f-{i}",
                [f"e-{i}"],
                target_id=f"t-{i % 5}",
                severity=["critical", "high", "medium", "low", "informational"][i % 5],
                attack_type=["prompt_injection", "jailbreak", "data_exfiltration",
                             "model_abuse", "denial_of_service"][i % 5],
                run_id=f"run-{i // 20}",
                provider=["openai", "anthropic", "google"][i % 3],
                model=["gpt-4", "claude-3-opus", "gemini-pro"][i % 3],
            )
            for i in range(200)
            if i % 3 != 0  # Only failures
        ]

        # Validation results
        validations = [
            ValidationResultInput(
                run_id=f"run-{i}",
                target_id=f"t-{i % 5}",
                organization_id="org-1",
                status="completed",
                total_checks=40,
                failed_checks=12 + i,
                passed_checks=28 - i,
                duration_ms=2000 + i * 100,
            )
            for i in range(10)
        ]

        # Produce risk incidents
        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings, chains, validations)

        # Should produce one incident per target
        assert len(incidents) == 5
        # All valid scores
        assert all(0.0 <= inc.risk_score.overall <= 10.0 for inc in incidents)
        # All have content
        assert all(inc.executive_summary for inc in incidents)
        assert all(inc.recommended_actions for inc in incidents)
        # Sorted by score
        scores = [inc.risk_score.overall for inc in incidents]
        assert scores == sorted(scores, reverse=True)


class TestRepeatedAttackPatterns:
    """Integration tests for repeated attack scenarios."""

    def test_persistent_attacker_same_target(self) -> None:
        """Simulate persistent attacker repeatedly hitting one target."""
        # 20 injection attempts across 4 runs
        evidence = [
            _evidence(
                f"e-{i}",
                run_id=f"run-{i // 5}",
                target_id="t-prod",
                attack_type="prompt_injection",
                minutes_offset=i * 10,
            )
            for i in range(20)
        ]

        correlation_engine = EvidenceCorrelationEngine()
        correlation_result = correlation_engine.correlate(evidence)

        chains = [
            EvidenceChainInput(
                chain_id=c.chain_id,
                evidence_ids=c.evidence_ids,
                attack_ids=c.attack_ids,
                run_id=c.run_id,
                target_id=c.target_id,
                correlation_score=c.correlation_score.value,
                summary=c.summary,
                timeline_start=c.timeline_start,
                timeline_end=c.timeline_end,
            )
            for c in correlation_result.attack_chains
        ]

        findings = [
            _finding_from_evidence(
                f"f-{i}",
                [f"e-{i}"],
                target_id="t-prod",
                severity="high",
                attack_type="prompt_injection",
                run_id=f"run-{i // 5}",
            )
            for i in range(20)
        ]

        validations = [
            ValidationResultInput(
                run_id=f"run-{i}",
                target_id="t-prod",
                organization_id="org-1",
                status="completed",
                total_checks=20,
                failed_checks=15,
                passed_checks=5,
                duration_ms=1000,
            )
            for i in range(4)
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings, chains, validations)

        assert len(incidents) == 1
        incident = incidents[0]
        # High score due to repetition, cross-validation, repeated target
        assert incident.risk_score.overall >= 7.0
        assert incident.priority in (RiskPriority.HIGH, RiskPriority.CRITICAL)
        # Repeated target factor should be maxed out
        target_factor = next(
            f for f in incident.risk_score.factors
            if f.factor_type == RiskFactorType.REPEATED_TARGET
        )
        assert target_factor.score == 1.0
        # Cross-validation should fire (4 runs)
        cross_factor = next(
            f for f in incident.risk_score.factors
            if f.factor_type == RiskFactorType.CROSS_VALIDATION
        )
        assert cross_factor.score >= 0.5

    def test_escalation_pattern(self) -> None:
        """Simulate attack escalation: recon → injection → exfil."""
        findings = [
            _finding_from_evidence(
                "f-recon", ["e1"], severity="low",
                attack_type="information_disclosure",
            ),
            _finding_from_evidence(
                "f-inject", ["e2", "e3"], severity="high",
                attack_type="prompt_injection",
            ),
            _finding_from_evidence(
                "f-exfil", ["e4", "e5"], severity="critical",
                attack_type="data_exfiltration",
            ),
        ]

        chains = [
            EvidenceChainInput(
                chain_id="escalation-chain",
                evidence_ids=["e1", "e2", "e3", "e4", "e5"],
                attack_ids=["a-recon", "a-inject", "a-exfil"],
                run_id="run-1",
                target_id="t-1",
                correlation_score=0.95,
                summary="Escalation: recon → injection → exfiltration",
                timeline_start=datetime(2025, 6, 1, 12, 0, tzinfo=UTC),
                timeline_end=datetime(2025, 6, 1, 12, 10, tzinfo=UTC),
            )
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings, chains)

        assert len(incidents) == 1
        incident = incidents[0]
        # Escalation with chain + critical severity should yield elevated risk
        assert incident.risk_score.overall >= 5.0
        assert len(incident.attack_types) == 3


class TestMixedSeverityIntegration:
    """Integration tests with mixed severity across providers."""

    def test_mixed_providers_and_models(self) -> None:
        """Different providers/models should produce varying risk weights."""
        findings = [
            _finding_from_evidence(
                "f1", ["e1"], severity="high",
                attack_type="prompt_injection",
                provider="openai", model="gpt-4",
            ),
            _finding_from_evidence(
                "f2", ["e2"], severity="high",
                attack_type="prompt_injection",
                provider="custom", model="internal-llm",
            ),
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings)

        assert len(incidents) == 1
        # Provider risk should reflect "custom" (0.8 > openai 0.7)
        provider_factor = next(
            f for f in incidents[0].risk_score.factors
            if f.factor_type == RiskFactorType.PROVIDER_RISK
        )
        assert provider_factor.score == 0.8

    def test_executive_summary_content(self) -> None:
        """Executive summary should include key metrics."""
        findings = [
            _finding_from_evidence("f1", ["e1"], severity="critical"),
            _finding_from_evidence("f2", ["e2"], severity="high"),
            _finding_from_evidence("f3", ["e3"], severity="medium"),
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings)

        summary = incidents[0].executive_summary
        assert "3 finding(s)" in summary
        assert "1 target(s)" in summary
        assert "Risk Score:" in summary

    def test_recommended_actions_for_high_risk(self) -> None:
        """High-risk incidents should recommend urgent action."""
        findings = [
            _finding_from_evidence(
                "f1", ["e1", "e2", "e3"],
                severity="critical",
                attack_type="prompt_injection",
            ),
        ]
        chains = [
            EvidenceChainInput(
                chain_id="c1",
                evidence_ids=["e1", "e2", "e3"],
                attack_ids=["a1"],
                run_id="run-1",
                target_id="t-1",
                correlation_score=0.95,
                summary="High-confidence injection chain",
                timeline_start=datetime(2025, 6, 1, 12, 0, tzinfo=UTC),
                timeline_end=datetime(2025, 6, 1, 12, 5, tzinfo=UTC),
            )
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings, chains)

        actions = incidents[0].recommended_actions
        assert len(actions) >= 2
        # Should mention investigation or remediation
        action_text = " ".join(actions).lower()
        assert "input" in action_text or "prompt" in action_text or "chain" in action_text


class TestIncidentMergeIntegration:
    """Integration tests for incident merging."""

    def test_merge_related_target_incidents(self) -> None:
        """Merge incidents from related targets."""
        findings = [
            _finding_from_evidence("f1", ["e1"], target_id="t-api-1", severity="high"),
            _finding_from_evidence("f2", ["e2"], target_id="t-api-2", severity="critical"),
        ]

        risk_engine = RiskCorrelationEngine()
        incidents = risk_engine.correlate(findings)
        assert len(incidents) == 2

        merged = risk_engine.merge_incidents(incidents)
        assert merged is not None
        assert set(merged.affected_targets) == {"t-api-1", "t-api-2"}
        assert "f1" in merged.finding_ids
        assert "f2" in merged.finding_ids
        assert merged.risk_score.overall > 0
        assert merged.status == IncidentStatus.OPEN

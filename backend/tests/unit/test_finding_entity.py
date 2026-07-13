"""Unit tests for Finding aggregate root."""

import pytest

from redforge.domain.findings.entity import Finding
from redforge.domain.findings.events import (
    FindingClosed,
    FindingCreated,
    FindingReopened,
    FindingRiskAccepted,
)
from redforge.domain.findings.exceptions import (
    FindingClosedError,
    InvalidFindingTransitionError,
)
from redforge.domain.findings.value_objects import (
    ComplianceReference,
    FindingStatus,
    MitreReference,
    OwaspReference,
    RiskScore,
    Severity,
)
from redforge.shared.identifiers import EntityId


def _create_finding(
    severity: Severity = Severity.HIGH,
    risk_score: float = 7.5,
) -> Finding:
    return Finding.create_from_evidence(
        organization_id=EntityId.generate(),
        run_id=EntityId.generate(),
        target_id=EntityId.generate(),
        evidence_ids=[EntityId.generate(), EntityId.generate()],
        title="Prompt Injection Vulnerability",
        description="Target responded to injected instructions",
        severity=severity,
        risk_score=RiskScore(score=risk_score),
        recommendation="Implement input filtering",
    )


class TestCreateFromEvidence:
    def test_creates_open_finding(self) -> None:
        f = _create_finding()
        assert f.status == FindingStatus.OPEN
        assert f.is_open is True

    def test_sets_fields(self) -> None:
        f = _create_finding(severity=Severity.CRITICAL, risk_score=9.5)
        assert f.severity == Severity.CRITICAL
        assert f.risk_score.score == 9.5
        assert f.title == "Prompt Injection Vulnerability"

    def test_requires_evidence(self) -> None:
        with pytest.raises(ValueError, match="at least one Evidence"):
            Finding.create_from_evidence(
                organization_id=EntityId.generate(),
                run_id=EntityId.generate(),
                target_id=EntityId.generate(),
                evidence_ids=[],
                title="No evidence",
                description="",
                severity=Severity.LOW,
                risk_score=RiskScore(score=2.0),
            )

    def test_requires_title_min_length(self) -> None:
        with pytest.raises(ValueError, match="at least 5"):
            Finding.create_from_evidence(
                organization_id=EntityId.generate(),
                run_id=EntityId.generate(),
                target_id=EntityId.generate(),
                evidence_ids=[EntityId.generate()],
                title="Hi",
                description="",
                severity=Severity.LOW,
                risk_score=RiskScore(score=1.0),
            )

    def test_emits_created_event(self) -> None:
        f = _create_finding()
        events = f.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], FindingCreated)
        assert events[0].severity == "high"

    def test_evidence_ids_as_tuple(self) -> None:
        f = _create_finding()
        assert len(f.evidence_ids) == 2
        assert isinstance(f.evidence_ids, tuple)


class TestAcceptRisk:
    def test_accepts(self) -> None:
        f = _create_finding()
        f.collect_events()
        f.accept_risk()
        assert f.status == FindingStatus.ACCEPTED

    def test_emits_event(self) -> None:
        f = _create_finding()
        f.collect_events()
        f.accept_risk()
        events = f.collect_events()
        assert isinstance(events[0], FindingRiskAccepted)

    def test_closed_cannot_accept(self) -> None:
        f = _create_finding()
        f.close()
        f.collect_events()
        with pytest.raises(InvalidFindingTransitionError):
            f.accept_risk()


class TestClose:
    def test_closes_open(self) -> None:
        f = _create_finding()
        f.collect_events()
        f.close()
        assert f.status == FindingStatus.CLOSED
        assert f.is_open is False

    def test_closes_accepted(self) -> None:
        f = _create_finding()
        f.accept_risk()
        f.collect_events()
        f.close()
        assert f.status == FindingStatus.CLOSED

    def test_emits_event(self) -> None:
        f = _create_finding()
        f.collect_events()
        f.close()
        events = f.collect_events()
        assert isinstance(events[0], FindingClosed)

    def test_already_closed_raises(self) -> None:
        f = _create_finding()
        f.close()
        f.collect_events()
        with pytest.raises(InvalidFindingTransitionError):
            f.close()


class TestReopen:
    def test_reopens_closed(self) -> None:
        f = _create_finding()
        f.close()
        f.collect_events()
        f.reopen()
        assert f.status == FindingStatus.REOPENED
        assert f.is_open is True

    def test_reopens_accepted(self) -> None:
        f = _create_finding()
        f.accept_risk()
        f.collect_events()
        f.reopen()
        assert f.status == FindingStatus.REOPENED

    def test_reopen_open_raises(self) -> None:
        f = _create_finding()
        f.collect_events()
        with pytest.raises(InvalidFindingTransitionError):
            f.reopen()

    def test_emits_event(self) -> None:
        f = _create_finding()
        f.close()
        f.collect_events()
        f.reopen()
        events = f.collect_events()
        assert isinstance(events[0], FindingReopened)


class TestReferences:
    def test_add_compliance_ref(self) -> None:
        f = _create_finding()
        ref = ComplianceReference(
            framework="SOC2", requirement_id="CC6.1", description="Logical access"
        )
        f.add_compliance_reference(ref)
        assert ref in f.compliance_refs

    def test_add_mitre_ref(self) -> None:
        f = _create_finding()
        ref = MitreReference(
            technique_id="AML.T0051",
            technique_name="LLM Prompt Injection",
            tactic="Initial Access",
        )
        f.add_mitre_reference(ref)
        assert ref in f.mitre_refs

    def test_add_owasp_ref(self) -> None:
        f = _create_finding()
        ref = OwaspReference(category_id="LLM01", category_name="Prompt Injection")
        f.add_owasp_reference(ref)
        assert ref in f.owasp_refs

    def test_closed_cannot_add_ref(self) -> None:
        f = _create_finding()
        f.close()
        with pytest.raises(FindingClosedError):
            f.add_compliance_reference(
                ComplianceReference(framework="X", requirement_id="Y")
            )

    def test_attach_recommendation(self) -> None:
        f = _create_finding()
        f.attach_recommendation("Use output filtering")
        assert f.recommendation == "Use output filtering"

    def test_recommendation_closed_raises(self) -> None:
        f = _create_finding()
        f.close()
        with pytest.raises(FindingClosedError):
            f.attach_recommendation("Too late")


class TestEquality:
    def test_same_id_equal(self) -> None:
        f = _create_finding()
        f2 = Finding(
            id=f.id,
            organization_id=EntityId.generate(),
            run_id=EntityId.generate(),
            target_id=EntityId.generate(),
            evidence_ids=[EntityId.generate()],
            title="Different",
            description="",
            severity=Severity.LOW,
            risk_score=RiskScore(score=1.0),
            status=FindingStatus.CLOSED,
            recommendation="",
            compliance_refs=[],
            mitre_refs=[],
            owasp_refs=[],
            timestamps=f.timestamps,
        )
        assert f == f2

    def test_different_id_not_equal(self) -> None:
        assert _create_finding() != _create_finding()

    def test_hashable(self) -> None:
        f = _create_finding()
        assert len({f, f}) == 1

"""Unit tests for Finding value objects."""

import pytest

from redforge.domain.findings.value_objects import (
    ComplianceReference,
    FindingStatus,
    MitreReference,
    OwaspReference,
    RiskScore,
    Severity,
)


class TestSeverity:
    def test_values(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFORMATIONAL == "informational"


class TestFindingStatus:
    def test_values(self) -> None:
        assert FindingStatus.OPEN == "open"
        assert FindingStatus.ACCEPTED == "accepted"
        assert FindingStatus.CLOSED == "closed"
        assert FindingStatus.REOPENED == "reopened"


class TestRiskScore:
    def test_valid(self) -> None:
        r = RiskScore(score=7.5)
        assert r.score == 7.5

    def test_severity_critical(self) -> None:
        assert RiskScore(score=9.5).severity_level == Severity.CRITICAL

    def test_severity_high(self) -> None:
        assert RiskScore(score=7.0).severity_level == Severity.HIGH

    def test_severity_medium(self) -> None:
        assert RiskScore(score=5.0).severity_level == Severity.MEDIUM

    def test_severity_low(self) -> None:
        assert RiskScore(score=2.0).severity_level == Severity.LOW

    def test_severity_informational(self) -> None:
        assert RiskScore(score=0.0).severity_level == Severity.INFORMATIONAL

    def test_below_zero_raises(self) -> None:
        with pytest.raises(ValueError, match=r"between 0\.0 and 10\.0"):
            RiskScore(score=-0.1)

    def test_above_ten_raises(self) -> None:
        with pytest.raises(ValueError, match=r"between 0\.0 and 10\.0"):
            RiskScore(score=10.1)

    def test_boundary_ten(self) -> None:
        r = RiskScore(score=10.0)
        assert r.severity_level == Severity.CRITICAL


class TestComplianceReference:
    def test_valid(self) -> None:
        ref = ComplianceReference(
            framework="SOC2", requirement_id="CC6.1", description="Access control"
        )
        assert ref.framework == "SOC2"

    def test_empty_framework_raises(self) -> None:
        with pytest.raises(ValueError, match="framework"):
            ComplianceReference(framework="", requirement_id="X")

    def test_empty_requirement_raises(self) -> None:
        with pytest.raises(ValueError, match="requirement_id"):
            ComplianceReference(framework="SOC2", requirement_id="")


class TestMitreReference:
    def test_valid(self) -> None:
        ref = MitreReference(
            technique_id="AML.T0051",
            technique_name="Prompt Injection",
            tactic="Initial Access",
        )
        assert ref.tactic == "Initial Access"

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="technique_id"):
            MitreReference(technique_id="", technique_name="X")

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="technique_name"):
            MitreReference(technique_id="X", technique_name="")


class TestOwaspReference:
    def test_valid(self) -> None:
        ref = OwaspReference(category_id="LLM01", category_name="Prompt Injection")
        assert ref.category_id == "LLM01"

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="category_id"):
            OwaspReference(category_id="", category_name="X")

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="category_name"):
            OwaspReference(category_id="X", category_name="")

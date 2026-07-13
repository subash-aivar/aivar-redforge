"""Unit tests for Validation value objects."""

import pytest

from redforge.domain.validations.value_objects import (
    TriggerType,
    ValidationStatus,
    ValidationSummary,
)


class TestValidationStatus:
    def test_values(self) -> None:
        assert ValidationStatus.SCHEDULED == "scheduled"
        assert ValidationStatus.RUNNING == "running"
        assert ValidationStatus.COMPLETED == "completed"
        assert ValidationStatus.FAILED == "failed"
        assert ValidationStatus.CANCELLED == "cancelled"


class TestTriggerType:
    def test_values(self) -> None:
        assert TriggerType.MANUAL == "manual"
        assert TriggerType.SCHEDULED == "scheduled"
        assert TriggerType.CI_CD == "ci_cd"
        assert TriggerType.POLICY == "policy"
        assert TriggerType.API == "api"


class TestValidationSummary:
    def test_valid_summary(self) -> None:
        s = ValidationSummary(
            total_checks=10, passed=7, failed=2, skipped=1, duration_ms=3000
        )
        assert s.total_checks == 10
        assert s.passed == 7
        assert s.failed == 2
        assert s.skipped == 1
        assert s.duration_ms == 3000

    def test_pass_rate(self) -> None:
        s = ValidationSummary(
            total_checks=10, passed=8, failed=1, skipped=1, duration_ms=1000
        )
        assert s.pass_rate == 80.0

    def test_pass_rate_zero_checks(self) -> None:
        s = ValidationSummary(
            total_checks=0, passed=0, failed=0, skipped=0, duration_ms=0
        )
        assert s.pass_rate == 0.0

    def test_pass_rate_all_passed(self) -> None:
        s = ValidationSummary(
            total_checks=5, passed=5, failed=0, skipped=0, duration_ms=500
        )
        assert s.pass_rate == 100.0

    def test_negative_total_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            ValidationSummary(
                total_checks=-1, passed=0, failed=0, skipped=0, duration_ms=0
            )

    def test_negative_passed_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            ValidationSummary(
                total_checks=0, passed=-1, failed=0, skipped=0, duration_ms=0
            )

    def test_negative_duration_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            ValidationSummary(
                total_checks=0, passed=0, failed=0, skipped=0, duration_ms=-1
            )

    def test_sum_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="must equal total_checks"):
            ValidationSummary(
                total_checks=10, passed=5, failed=3, skipped=1, duration_ms=100
            )

    def test_immutable(self) -> None:
        s = ValidationSummary(
            total_checks=1, passed=1, failed=0, skipped=0, duration_ms=10
        )
        with pytest.raises(AttributeError):
            s.total_checks = 99  # type: ignore[misc]

    def test_equality(self) -> None:
        s1 = ValidationSummary(
            total_checks=5, passed=3, failed=1, skipped=1, duration_ms=200
        )
        s2 = ValidationSummary(
            total_checks=5, passed=3, failed=1, skipped=1, duration_ms=200
        )
        assert s1 == s2

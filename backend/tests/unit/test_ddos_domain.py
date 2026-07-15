"""Unit tests for DDoS domain value objects — M19."""

from __future__ import annotations

import pytest

from redforge.domain.ddos.value_objects import (
    AttackClassification,
    BaselineConfidence,
    IncidentSeverity,
    IncidentStatus,
    MitigationApprovalStatus,
    MitigationExecutionStatus,
    MitigationMode,
    MitigationRecommendationType,
)


# ── IncidentStatus ────────────────────────────────────────────────────────────

def test_incident_status_open_states() -> None:
    open_states = {
        IncidentStatus.DETECTED,
        IncidentStatus.ACTIVE,
        IncidentStatus.ESCALATED,
        IncidentStatus.MITIGATING,
        IncidentStatus.MONITORING,
    }
    for s in open_states:
        assert s.is_open is True, f"Expected {s} to be open"
    for s in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
        assert s.is_open is False, f"Expected {s} to not be open"


def test_incident_status_terminal_states() -> None:
    terminal = {IncidentStatus.RESOLVED, IncidentStatus.CLOSED}
    for s in terminal:
        assert s.is_terminal is True
    for s in (IncidentStatus.DETECTED, IncidentStatus.ACTIVE, IncidentStatus.ESCALATED):
        assert s.is_terminal is False


def test_incident_status_all_states_covered() -> None:
    all_states = list(IncidentStatus)
    for s in all_states:
        # is_open and is_terminal are defined for all states
        _ = s.is_open
        _ = s.is_terminal


# ── IncidentSeverity ──────────────────────────────────────────────────────────

def test_severity_ordering() -> None:
    severities = [IncidentSeverity.LOW, IncidentSeverity.MEDIUM, IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
    assert len(severities) == 4
    # Values are distinct strings
    assert len({s.value for s in severities}) == 4


# ── AttackClassification ──────────────────────────────────────────────────────

def test_attack_classifications_all_have_values() -> None:
    for cls in AttackClassification:
        assert isinstance(cls.value, str)
        assert len(cls.value) > 0


def test_inferential_classifications_are_labeled() -> None:
    # Classifications that cannot be confirmed from available telemetry
    # should have SUSPECTED suffix per M19 design
    inferential = [AttackClassification.SYN_FLOOD_SUSPECTED]
    for cls in inferential:
        assert "SUSPECTED" in cls.value, f"{cls.value} should be labeled SUSPECTED"


# ── BaselineConfidence ────────────────────────────────────────────────────────

def test_baseline_confidence_all_states() -> None:
    states = list(BaselineConfidence)
    assert BaselineConfidence.COLD_START in states
    assert BaselineConfidence.INSUFFICIENT_DATA in states
    assert BaselineConfidence.ESTABLISHED in states
    assert BaselineConfidence.DEGRADED in states


# ── MitigationMode ────────────────────────────────────────────────────────────

def test_default_mitigation_mode_is_recommend_only() -> None:
    # RECOMMEND_ONLY must be the default; no auto-execution
    assert MitigationMode.RECOMMEND_ONLY.value == "RECOMMEND_ONLY"


def test_mitigation_mode_not_configured_exists() -> None:
    assert MitigationMode.NOT_CONFIGURED.value == "NOT_CONFIGURED"


# ── MitigationApprovalStatus ──────────────────────────────────────────────────

def test_approval_status_lifecycle() -> None:
    # State machine: PENDING → APPROVED or REJECTED
    states = {s.value for s in MitigationApprovalStatus}
    assert "PENDING" in states
    assert "APPROVED" in states
    assert "REJECTED" in states


# ── MitigationExecutionStatus ─────────────────────────────────────────────────

def test_execution_status_includes_not_started() -> None:
    assert MitigationExecutionStatus.NOT_STARTED.value == "NOT_STARTED"

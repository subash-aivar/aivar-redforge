"""CSPMFinding lifecycle transition tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from redforge.domain.cloud_security.cspm.entities import (
    FindingEvidence,
    RemediationReference,
)
from redforge.domain.cloud_security.cspm.exceptions import (
    InvalidCSPMArgumentError,
    InvalidFindingTransitionError,
)
from redforge.domain.cloud_security.cspm.finding import CSPMFinding
from redforge.domain.cloud_security.cspm.value_objects import (
    ComplianceRef,
    CSPMPolicyId,
    CSPMRuleId,
    FindingSeverity,
    FindingStatus,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId


def _open_finding() -> CSPMFinding:
    return CSPMFinding.open(
        cloud_asset_id=CloudAssetId(uuid4()),
        organization_id=OrganizationId("01HXORG0000000000000000001"),
        policy_id=CSPMPolicyId("CSPM-AWS-S3-001"),
        rule_id=CSPMRuleId("S3_PUBLIC_EXPOSURE"),
        severity=FindingSeverity.CRITICAL,
        title="Public bucket",
        description="Bucket is public",
        remediation=RemediationReference(description="Lock it down"),
        compliance_mapping=[
            ComplianceRef(framework_key="cis_benchmarks_v8", requirement_ref="3.3")
        ],
        evidence=[
            FindingEvidence.create(
                path="normalized_config.network_exposure",
                expected="PRIVATE",
                actual="PUBLIC",
                message="public",
            )
        ],
        config_hash="abc123",
    )


def test_open_creates_open_status() -> None:
    finding = _open_finding()
    assert finding.status is FindingStatus.OPEN
    assert finding.version == 1
    assert finding.fingerprint.endswith(str(finding.cloud_asset_id))


def test_open_requires_title() -> None:
    with pytest.raises(InvalidCSPMArgumentError):
        CSPMFinding.open(
            cloud_asset_id=CloudAssetId(uuid4()),
            organization_id=OrganizationId("01HXORG0000000000000000001"),
            policy_id=CSPMPolicyId("P1"),
            rule_id=CSPMRuleId("R1"),
            severity=FindingSeverity.LOW,
            title="  ",
            description="d",
            remediation=RemediationReference(description=""),
            compliance_mapping=[],
            evidence=[],
            config_hash="h",
        )


def test_confirm_from_open() -> None:
    finding = _open_finding()
    finding.confirm(changed_by="analyst")
    assert finding.status is FindingStatus.CONFIRMED


def test_suppress_from_open() -> None:
    finding = _open_finding()
    until = datetime.now(UTC) + timedelta(days=7)
    finding.suppress(changed_by="analyst", reason="false positive", until=until)
    assert finding.status is FindingStatus.SUPPRESSED
    assert finding.suppressed_until == until


def test_accept_risk_from_open() -> None:
    finding = _open_finding()
    finding.accept_risk(accepted_by="owner", reason="business exception")
    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert finding.accepted_by == "owner"


def test_accept_risk_requires_fields() -> None:
    finding = _open_finding()
    with pytest.raises(InvalidCSPMArgumentError):
        finding.accept_risk(accepted_by="", reason="x")
    with pytest.raises(InvalidCSPMArgumentError):
        finding.accept_risk(accepted_by="owner", reason="")


def test_resolve_from_open() -> None:
    finding = _open_finding()
    finding.resolve(changed_by="system")
    assert finding.status is FindingStatus.RESOLVED
    assert finding.resolved_at is not None


def test_expire_from_open() -> None:
    finding = _open_finding()
    finding.expire()
    assert finding.status is FindingStatus.EXPIRED


def test_reopen_from_resolved() -> None:
    finding = _open_finding()
    finding.resolve(changed_by="system")
    finding.reopen(changed_by="system")
    assert finding.status is FindingStatus.REOPENED
    assert finding.resolved_at is None
    assert finding.reopened_at is not None


def test_confirm_from_reopened() -> None:
    finding = _open_finding()
    finding.resolve(changed_by="system")
    finding.reopen(changed_by="system")
    finding.confirm(changed_by="analyst")
    assert finding.status is FindingStatus.CONFIRMED


def test_resolve_from_confirmed() -> None:
    finding = _open_finding()
    finding.confirm(changed_by="a")
    finding.resolve(changed_by="a")
    assert finding.status is FindingStatus.RESOLVED


def test_suppress_from_confirmed() -> None:
    finding = _open_finding()
    finding.confirm(changed_by="a")
    finding.suppress(changed_by="a", reason="noise")
    assert finding.status is FindingStatus.SUPPRESSED


def test_accept_from_confirmed() -> None:
    finding = _open_finding()
    finding.confirm(changed_by="a")
    finding.accept_risk(accepted_by="a", reason="ok")
    assert finding.status is FindingStatus.ACCEPTED_RISK


def test_expire_from_confirmed() -> None:
    finding = _open_finding()
    finding.confirm(changed_by="a")
    finding.expire()
    assert finding.status is FindingStatus.EXPIRED


def test_open_from_suppressed() -> None:
    finding = _open_finding()
    finding.suppress(changed_by="a", reason="tmp")
    finding._transition(FindingStatus.OPEN, changed_by="a", reason="unsuspend")
    assert finding.status is FindingStatus.OPEN


def test_reopen_from_suppressed() -> None:
    finding = _open_finding()
    finding.suppress(changed_by="a", reason="tmp")
    finding.reopen(changed_by="a")
    assert finding.status is FindingStatus.REOPENED


def test_expire_from_suppressed() -> None:
    finding = _open_finding()
    finding.suppress(changed_by="a", reason="tmp")
    finding.expire()
    assert finding.status is FindingStatus.EXPIRED


def test_open_from_accepted_risk() -> None:
    finding = _open_finding()
    finding.accept_risk(accepted_by="a", reason="ok")
    finding._transition(FindingStatus.OPEN, changed_by="a", reason="revoke")
    assert finding.status is FindingStatus.OPEN


def test_reopen_from_accepted_risk() -> None:
    finding = _open_finding()
    finding.accept_risk(accepted_by="a", reason="ok")
    finding.reopen(changed_by="a")
    assert finding.status is FindingStatus.REOPENED


def test_resolve_from_accepted_risk() -> None:
    finding = _open_finding()
    finding.accept_risk(accepted_by="a", reason="ok")
    finding.resolve(changed_by="a")
    assert finding.status is FindingStatus.RESOLVED


def test_reopen_from_expired() -> None:
    finding = _open_finding()
    finding.expire()
    finding.reopen(changed_by="system")
    assert finding.status is FindingStatus.REOPENED


def test_open_from_expired() -> None:
    finding = _open_finding()
    finding.expire()
    finding._transition(FindingStatus.OPEN, changed_by="system", reason="revive")
    assert finding.status is FindingStatus.OPEN


def test_invalid_resolve_from_resolved() -> None:
    finding = _open_finding()
    finding.resolve(changed_by="a")
    with pytest.raises(InvalidFindingTransitionError):
        finding.resolve(changed_by="a")


def test_invalid_confirm_from_resolved() -> None:
    finding = _open_finding()
    finding.resolve(changed_by="a")
    with pytest.raises(InvalidFindingTransitionError):
        finding.confirm(changed_by="a")


def test_invalid_suppress_from_resolved() -> None:
    finding = _open_finding()
    finding.resolve(changed_by="a")
    with pytest.raises(InvalidFindingTransitionError):
        finding.suppress(changed_by="a", reason="x")


def test_invalid_accept_from_expired() -> None:
    finding = _open_finding()
    finding.expire()
    with pytest.raises(InvalidFindingTransitionError):
        finding.accept_risk(accepted_by="a", reason="x")


def test_touch_seen_updates_hash_and_version() -> None:
    finding = _open_finding()
    v = finding.version
    finding.touch_seen(
        evidence=[
            FindingEvidence.create(path="p", expected="e", actual="a", message="m")
        ],
        config_hash="newhash",
    )
    assert finding.config_hash == "newhash"
    assert finding.version == v + 1


def test_pop_events_clears_pending() -> None:
    finding = _open_finding()
    events = finding.pop_events()
    assert events
    assert finding.pop_events() == []


def test_fingerprint_builder() -> None:
    fp = CSPMFinding.build_fingerprint("P", "R", "A")
    assert fp == "P:R:A"


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        ("confirm", {"changed_by": "a"}),
        ("suppress", {"changed_by": "a", "reason": "r"}),
        ("accept_risk", {"accepted_by": "a", "reason": "r"}),
        ("resolve", {"changed_by": "a"}),
        ("expire", {}),
    ],
)
def test_transitions_from_reopened(method: str, kwargs: dict) -> None:
    finding = _open_finding()
    finding.resolve(changed_by="a")
    finding.reopen(changed_by="a")
    getattr(finding, method)(**kwargs)
    assert finding.status is not FindingStatus.REOPENED

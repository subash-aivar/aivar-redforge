"""DetectionException aggregate tests — Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from detection.domain.events.exception_events import (
    DetectionExceptionApproved,
    DetectionExceptionExpired,
    DetectionExceptionRejected,
    DetectionExceptionRenewed,
    DetectionExceptionRequested,
    DetectionExceptionRevoked,
)
from detection.domain.exceptions.domain_exceptions import (
    ComplianceAcknowledgementRequired,
    ExceptionLifecycleBlocked,
)
from detection.domain.value_objects.enums import ExceptionState, ExceptionType
from detection.domain.value_objects.exception_vos import ExceptionApprover
from tests.detection.phase4_helpers import make_exception


def test_request_emits_event() -> None:
    exc = make_exception()
    assert exc.state == ExceptionState.PENDING
    assert any(isinstance(e, DetectionExceptionRequested) for e in exc.pop_events())


@pytest.mark.parametrize("etype", list(ExceptionType))
def test_all_exception_types(etype: ExceptionType) -> None:
    from detection.domain.aggregates.detection_exception import DetectionException
    from detection.domain.value_objects.enums import ExceptionScopeKind
    from detection.domain.value_objects.exception_vos import (
        AffectedRuleRefs,
        ExceptionJustification,
        ExceptionScope,
    )
    from tests.detection.phase4_helpers import make_tenant

    tid = make_tenant()
    now = datetime.now(UTC)
    rid = str(uuid4())
    exc = DetectionException.request(
        tenant_id=tid,
        exception_type=etype,
        scope=ExceptionScope(kind=ExceptionScopeKind.RULE, rule_id=rid),
        justification=ExceptionJustification(text="j"),
        requester="r",
        valid_until=now + timedelta(days=1),
        affected_rules=AffectedRuleRefs(rule_ids=(rid,)),
        now=now,
    )
    assert exc.exception_type == etype


def test_compliance_requires_ack() -> None:
    with pytest.raises(ComplianceAcknowledgementRequired):
        make_exception(compliance_mapped=True, acknowledged=False)


def test_approve_reject_expire_renew_revoke() -> None:
    now = datetime.now(UTC)
    exc = make_exception(now=now)
    tid = exc.tenant_id
    exc.approve(tenant_id=tid, approver=ExceptionApprover("boss"), now=now)
    assert exc.state == ExceptionState.ACTIVE
    assert any(isinstance(e, DetectionExceptionApproved) for e in exc.pop_events())

    exc2 = make_exception(now=now)
    exc2.reject(tenant_id=exc2.tenant_id, rejector="boss", reason="no", now=now)
    assert exc2.state == ExceptionState.REJECTED
    assert any(isinstance(e, DetectionExceptionRejected) for e in exc2.pop_events())

    exc3 = make_exception(now=now, valid_hours=1)
    exc3.approve(tenant_id=exc3.tenant_id, approver=ExceptionApprover("a"), now=now)
    future = now + timedelta(hours=2)
    exc3.expire(tenant_id=exc3.tenant_id, now=future)
    assert exc3.state == ExceptionState.EXPIRED
    assert any(isinstance(e, DetectionExceptionExpired) for e in exc3.pop_events())

    exc3.renew(
        tenant_id=exc3.tenant_id,
        renewer="a",
        new_valid_until=future + timedelta(days=1),
        now=future,
    )
    assert exc3.state == ExceptionState.ACTIVE
    assert any(isinstance(e, DetectionExceptionRenewed) for e in exc3.pop_events())

    exc3.revoke(tenant_id=exc3.tenant_id, revoker="a", reason="done", now=future)
    assert exc3.state == ExceptionState.REVOKED
    assert any(isinstance(e, DetectionExceptionRevoked) for e in exc3.pop_events())


def test_cannot_expire_early() -> None:
    now = datetime.now(UTC)
    exc = make_exception(now=now)
    exc.approve(tenant_id=exc.tenant_id, approver=ExceptionApprover("a"), now=now)
    with pytest.raises(ExceptionLifecycleBlocked):
        exc.expire(tenant_id=exc.tenant_id, now=now)


@pytest.mark.parametrize("i", range(25))
def test_request_variants(i: int) -> None:
    exc = make_exception(valid_hours=i + 1)
    assert exc.state == ExceptionState.PENDING

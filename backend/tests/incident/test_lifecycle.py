from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from analytics.domain.services.kpi_computation_service import KPIComputationService
from analytics.domain.value_objects.enums import KPIStatus, KPIType
from incident.application.commands.incident_commands import (
    AuthorizeContainmentCommand,
    ClassifyIncidentCommand,
    CloseIncidentCommand,
    CompleteContainmentCommand,
    DeclareIncidentCommand,
    LogCommunicationCommand,
    ReclassifyIncidentCommand,
    SubmitEradicationCommand,
    VerifyEradicationCommand,
)
from incident.application.exceptions import ApplicationNotFoundError
from incident.domain.exceptions.domain_exceptions import (
    AuthorizationDenied,
    ClosureRequirementsNotMet,
    DomainInvariantViolation,
)
from incident.domain.repositories.i_incident_repositories import IIncidentCommunicationLogRepository
from incident.domain.services.containment_authorization_service import (
    ContainmentAuthorizationService,
)
from incident.domain.value_objects.enums import ContainmentActionType, IncidentSeverity
from incident.infrastructure.container import IncidentContainer


@pytest.mark.asyncio
async def test_full_lifecycle_and_mttr_publish() -> None:
    c = IncidentContainer()
    tenant = uuid4()
    roles_a = ("incident:analyst",)
    roles_c = ("incident:commander",)
    d = await c.app.declare(
        DeclareIncidentCommand(tenant, "T", "D", "MANUAL_DECLARATION", "P2_HIGH", "a1", roles_a)
    )
    iid = __import__("uuid").UUID(d.incident_id)
    await c.app.classify(
        ClassifyIncidentCommand(tenant, iid, "P2_HIGH", "MANUAL_DECLARATION", "a1", roles_a)
    )
    action = await c.app.authorize_containment(
        AuthorizeContainmentCommand(tenant, iid, "ALERT_ESCALATION", "esc", "a1", roles_a)
    )
    await c.app.complete_containment(
        CompleteContainmentCommand(
            tenant, __import__("uuid").UUID(action.action_id), "ev-1", "a1", roles_a
        )
    )
    await c.app.submit_eradication(
        SubmitEradicationCommand(tenant, iid, "clean", ("e1",), "a1", roles_a)
    )
    await c.app.verify_eradication(VerifyEradicationCommand(tenant, iid, "commander1", roles_c))
    closed = await c.app.close(
        CloseIncidentCommand(tenant, iid, "threat_contained", "commander1", roles_c)
    )
    assert closed.phase == "CLOSED"
    assert any(r["event_type"] == "incident_classified" for r in c.analytics.rows)
    assert any(r["event_type"] == "incident_closed" for r in c.analytics.rows)


@pytest.mark.asyncio
async def test_network_isolation_requires_ciso() -> None:
    c = IncidentContainer()
    tenant = uuid4()
    d = await c.app.declare(
        DeclareIncidentCommand(
            tenant, "T", "D", "MANUAL_DECLARATION", "P1_CRITICAL", "a1", ("incident:analyst",)
        )
    )
    iid = __import__("uuid").UUID(d.incident_id)
    await c.app.classify(
        ClassifyIncidentCommand(
            tenant, iid, "P1_CRITICAL", "MANUAL_DECLARATION", "a1", ("incident:analyst",)
        )
    )
    with pytest.raises(AuthorizationDenied):
        await c.app.authorize_containment(
            AuthorizeContainmentCommand(
                tenant, iid, "NETWORK_ISOLATION", "iso", "a1", ("incident:analyst",)
            )
        )


def test_containment_matrix() -> None:
    svc = ContainmentAuthorizationService()
    assert svc.required_authorization_level(ContainmentActionType.NETWORK_ISOLATION).value == "CISO"
    assert (
        svc.required_authorization_level(ContainmentActionType.ALERT_ESCALATION).value == "ANALYST"
    )


@pytest.mark.asyncio
async def test_reclassify_justification() -> None:
    c = IncidentContainer()
    tenant = uuid4()
    d = await c.app.declare(
        DeclareIncidentCommand(
            tenant, "T", "D", "MANUAL_DECLARATION", "P3_MEDIUM", "a1", ("incident:analyst",)
        )
    )
    iid = __import__("uuid").UUID(d.incident_id)
    await c.app.classify(
        ClassifyIncidentCommand(
            tenant, iid, "P3_MEDIUM", "MANUAL_DECLARATION", "a1", ("incident:analyst",)
        )
    )
    with pytest.raises(DomainInvariantViolation):
        await c.app.reclassify(
            ReclassifyIncidentCommand(
                tenant, iid, "P1_CRITICAL", "too short", "c1", ("incident:commander",)
            )
        )
    ok = await c.app.reclassify(
        ReclassifyIncidentCommand(
            tenant,
            iid,
            "P1_CRITICAL",
            "Material impact confirmed by detection",
            "c1",
            ("incident:commander",),
        )
    )
    assert ok.severity == "P1_CRITICAL"


@pytest.mark.asyncio
async def test_close_blocked_without_eradication() -> None:
    c = IncidentContainer()
    tenant = uuid4()
    d = await c.app.declare(
        DeclareIncidentCommand(
            tenant, "T", "D", "MANUAL_DECLARATION", "P2_HIGH", "a1", ("incident:analyst",)
        )
    )
    iid = __import__("uuid").UUID(d.incident_id)
    await c.app.classify(
        ClassifyIncidentCommand(
            tenant, iid, "P2_HIGH", "MANUAL_DECLARATION", "a1", ("incident:analyst",)
        )
    )
    with pytest.raises(ClosureRequirementsNotMet):
        await c.app.close(
            CloseIncidentCommand(tenant, iid, "threat_contained", "c1", ("incident:commander",))
        )


@pytest.mark.asyncio
async def test_comm_log_hash_chain_and_interface() -> None:
    methods = {m for m in dir(IIncidentCommunicationLogRepository) if not m.startswith("_")}
    assert "append" in methods and "find_by_incident" in methods
    assert "update" not in methods and "delete" not in methods
    c = IncidentContainer()
    tenant = uuid4()
    d = await c.app.declare(
        DeclareIncidentCommand(
            tenant, "T", "D", "MANUAL_DECLARATION", "P4_LOW", "a1", ("incident:analyst",)
        )
    )
    iid = __import__("uuid").UUID(d.incident_id)
    await c.app.log_communication(
        LogCommunicationCommand(
            tenant, iid, "hello", "INTERNAL", "soc", "a1", ("incident:analyst",)
        )
    )
    await c.app.log_communication(
        LogCommunicationCommand(
            tenant, iid, "world", "INTERNAL", "soc", "a1", ("incident:analyst",)
        )
    )
    rows = await c.app.get_comm_log(tenant, iid, ("incident:viewer",))
    assert len(rows) == 2
    assert rows[0].entry_hash
    assert rows[1].prev_hash == rows[0].entry_hash


@pytest.mark.asyncio
async def test_tenant_isolation() -> None:
    c = IncidentContainer()
    t1, t2 = uuid4(), uuid4()
    d = await c.app.declare(
        DeclareIncidentCommand(
            t1, "T", "D", "MANUAL_DECLARATION", "P2_HIGH", "a1", ("incident:analyst",)
        )
    )
    listed = await c.app.list_incidents(t2, ("incident:viewer",))
    assert listed == []
    with pytest.raises(ApplicationNotFoundError):
        await c.app.get_incident(t2, __import__("uuid").UUID(d.incident_id), ("incident:viewer",))


@pytest.mark.asyncio
async def test_mttr_kpi_activates() -> None:
    c = IncidentContainer()
    tenant = uuid4()
    rows = []
    for _ in range(3):
        d = await c.app.declare(
            DeclareIncidentCommand(
                tenant, "T", "D", "MANUAL_DECLARATION", "P2_HIGH", "a1", ("incident:analyst",)
            )
        )
        iid = __import__("uuid").UUID(d.incident_id)
        await c.app.classify(
            ClassifyIncidentCommand(
                tenant, iid, "P2_HIGH", "MANUAL_DECLARATION", "a1", ("incident:analyst",)
            )
        )
        action = await c.app.authorize_containment(
            AuthorizeContainmentCommand(
                tenant, iid, "TRAFFIC_LOGGING", "log", "a1", ("incident:analyst",)
            )
        )
        await c.app.complete_containment(
            CompleteContainmentCommand(
                tenant, __import__("uuid").UUID(action.action_id), "ev", "a1", ("incident:analyst",)
            )
        )
        await c.app.submit_eradication(
            SubmitEradicationCommand(tenant, iid, "clean", ("e1",), "a1", ("incident:analyst",))
        )
        await c.app.verify_eradication(
            VerifyEradicationCommand(tenant, iid, "c1", ("incident:commander",))
        )
        await c.app.close(
            CloseIncidentCommand(tenant, iid, "threat_contained", "c1", ("incident:commander",))
        )
    # normalize timestamps for KPI service
    kpi_rows = []
    for r in c.analytics.rows:
        row = dict(r)
        for k in ("classified_at", "closed_at", "event_ts"):
            if isinstance(row.get(k), str):
                row[k] = datetime.fromisoformat(row[k])
        kpi_rows.append(row)
    result = KPIComputationService().compute(
        KPIType.MTTR,
        tenant_id=tenant,
        events={"incident": kpi_rows},
        period_end=datetime.now(UTC) + timedelta(days=1),
    )
    assert result.status == KPIStatus.ACTIVE
    assert result.value is not None


def test_severity_mapping() -> None:
    from incident.domain.services.severity_classification_service import (
        SeverityClassificationService,
    )

    assert (
        SeverityClassificationService().from_finding_severity("critical")
        == IncidentSeverity.P1_CRITICAL
    )

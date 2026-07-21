from __future__ import annotations

from uuid import uuid4

import pytest

from exposure_reporting.application.commands.reporting_commands import (
    CreateBusinessImpactMappingCommand,
    GenerateExposureReportCommand,
    UpdateBusinessImpactMappingCommand,
)
from exposure_reporting.application.exceptions import (
    ApplicationConflictError,
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from exposure_reporting.infrastructure.acl.exposure_data_query_adapter import (
    StaticExposureDataQueryAdapter,
)
from exposure_reporting.infrastructure.acl.security_graph_write_adapter import (
    InMemorySecurityGraphWriteAdapter,
)
from exposure_reporting.infrastructure.container import ExposureReportingContainer

ANALYST = ("exposure:analyst",)
ENGINEER = ("exposure:engineer",)
VIEWER = ("exposure:viewer",)
ADMIN = ("exposure:admin",)


@pytest.fixture
def container() -> ExposureReportingContainer:
    graph = InMemorySecurityGraphWriteAdapter()
    return ExposureReportingContainer(
        exposure_port=StaticExposureDataQueryAdapter(
            asset_scores={"a1": 8.0, "a2": 3.0},
            amplifier_weight_prevalence={"KevPresent": 5.0, "DetectionGap": 1.0},
            score_input_version=2,
            threat_cache_stale=True,
        ),
        graph_port=graph,
    )


@pytest.mark.asyncio
async def test_generate_board_report_and_graph(container: ExposureReportingContainer) -> None:
    tenant = uuid4()
    dto = await container.report_service.generate(
        GenerateExposureReportCommand(
            tenant_id=tenant,
            report_type="BoardRiskSummary",
            generated_by="analyst@aivar",
            actor_roles=ANALYST,
        )
    )
    assert dto.report_type == "BoardRiskSummary"
    assert dto.template_id == "Critical Exploit Availability"
    assert dto.data_freshness_warning is True
    assert "executive_kpis" in dto.content
    assert isinstance(container.graph_port, InMemorySecurityGraphWriteAdapter)
    assert len(container.graph_port.nodes) >= 1
    assert len(container.graph_port.edges) >= 1


@pytest.mark.asyncio
async def test_all_core_report_types(container: ExposureReportingContainer) -> None:
    tenant = uuid4()
    for rtype in (
        "BoardRiskSummary",
        "RemediationRoadmap",
        "ComplianceGapReport",
        "TenantExposureDashboard",
        "ExposureScoreTrend",
    ):
        dto = await container.report_service.generate(
            GenerateExposureReportCommand(
                tenant_id=tenant,
                report_type=rtype,
                generated_by="analyst",
                actor_roles=ANALYST,
            )
        )
        assert dto.report_type == rtype


@pytest.mark.asyncio
async def test_business_impact_crud_tenant_isolation(
    container: ExposureReportingContainer,
) -> None:
    tenant_a = uuid4()
    tenant_b = uuid4()
    asset = uuid4()
    created = await container.mapping_service.create(
        CreateBusinessImpactMappingCommand(
            tenant_id=tenant_a,
            asset_ref_id=asset,
            criticality="MissionCritical",
            impact_domain="Revenue",
            authored_by="eng",
            regulatory_scope=("PCI DSS",),
            actor_roles=ENGINEER,
        )
    )
    assert created.criticality == "MissionCritical"
    with pytest.raises(ApplicationNotFoundError):
        await container.mapping_service.get_by_asset(tenant_b, asset, VIEWER)
    updated = await container.mapping_service.update(
        UpdateBusinessImpactMappingCommand(
            tenant_id=tenant_a,
            asset_ref_id=asset,
            criticality="High",
            impact_domain="Compliance",
            authored_by="eng2",
            actor_roles=ENGINEER,
        )
    )
    assert updated.criticality == "High"
    with pytest.raises(ApplicationConflictError):
        await container.mapping_service.create(
            CreateBusinessImpactMappingCommand(
                tenant_id=tenant_a,
                asset_ref_id=asset,
                criticality="Low",
                impact_domain="General",
                authored_by="eng",
                actor_roles=ENGINEER,
            )
        )


@pytest.mark.asyncio
async def test_viewer_cannot_generate(container: ExposureReportingContainer) -> None:
    with pytest.raises(ApplicationForbiddenError):
        await container.report_service.generate(
            GenerateExposureReportCommand(
                tenant_id=uuid4(),
                report_type="BoardRiskSummary",
                generated_by="v",
                actor_roles=VIEWER,
            )
        )


@pytest.mark.asyncio
async def test_dashboard_trends_rebuild(container: ExposureReportingContainer) -> None:
    tenant = uuid4()
    dash = await container.dashboard.get_dashboard(tenant, VIEWER)
    assert dash.asset_count == 2
    assert dash.dominant_amplifier == "KevPresent"
    trends = await container.dashboard.get_trends(tenant, VIEWER)
    assert len(trends.points) >= 1
    rebuilt = await container.projections.rebuild_read_models(tenant, ADMIN)
    assert rebuilt["ok"] is True
    repaired = await container.projections.repair_projections(tenant, ADMIN)
    assert repaired["repaired"] is True

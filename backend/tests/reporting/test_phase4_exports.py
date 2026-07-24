from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from redforge.shared.identifiers import EntityId
from reporting.application.commands.reporting_commands import GenerateReportOnDemandCommand
from reporting.application.exceptions import ApplicationRateLimitedError
from reporting.domain.ports.i_ml_signal_query_port import MLSignalBundleDTO, MLSignalDTO
from reporting.domain.services.bi_export_rate_limiter import BIExportRateLimiter
from reporting.domain.services.report_export_service import ReportExportService
from reporting.domain.services.report_generation_service import ReportGenerationService
from reporting.domain.value_objects.enums import ReportFormat, ReportType
from reporting.infrastructure.acl.ml_signal_query_adapter import StubMLSignalQueryAdapter
from reporting.infrastructure.container import ReportingContainer


def test_export_csv_xlsx_pdf() -> None:
    svc = ReportExportService()
    content = {
        "title": "T",
        "kpis": [{"kpi_type": "MTTD", "value": 1.0, "unit": "h"}],
    }
    for fmt in (ReportFormat.CSV, ReportFormat.XLSX, ReportFormat.PDF, ReportFormat.JSON):
        payload, ctype = svc.export(content, fmt=fmt, narrative="n")
        assert len(payload) > 0
        assert ctype


def test_predictive_forecast_ml_and_cold_start() -> None:
    gen = ReportGenerationService()
    ml = MLSignalBundleDTO(
        signals=(
            MLSignalDTO("risk", "a1", 0.9, technique_id="T1059", exploitation_probability=0.95),
            MLSignalDTO("risk", "a2", 0.2, technique_id="T1003", exploitation_probability=0.2),
        ),
        model_deployed=True,
    )
    top, source = gen.select_top_techniques(ml, {}, top_n=1)
    assert source == "ml_model"
    assert top[0]["technique_id"] == "T1059"

    top2, source2 = gen.select_top_techniques(
        MLSignalBundleDTO(signals=(), model_deployed=False),
        {
            "fallback_techniques": [
                {"technique_id": "T1110", "cvss": 9.0, "exposure_score": 4.0},
                {"technique_id": "T1021", "cvss": 5.0, "exposure_score": 1.0},
            ]
        },
        top_n=1,
    )
    assert source2 == "rule_based_fallback"
    assert top2[0]["technique_id"] == "T1110"


def test_rate_limit_11th_denied() -> None:
    limiter = BIExportRateLimiter(limit=10, window_seconds=60)
    tid = uuid4()
    for _ in range(10):
        d = limiter.check(tid, actor="a", export_format="CSV", dataset_or_instance_ref="x")
        assert d.allowed is True
    denied = limiter.check(tid, actor="a", export_format="CSV", dataset_or_instance_ref="x")
    assert denied.allowed is False


@pytest.mark.asyncio
async def test_delivery_email_and_webhook_audit() -> None:
    c = ReportingContainer()
    tid = EntityId.generate()
    template_id = c.template_id_for(ReportType.DETECTION_ANALYTICS_REPORT)
    assert template_id
    dto = await c.app.generate_on_demand(
        GenerateReportOnDemandCommand(
            tenant_id=tid,
            template_id=UUID(template_id),
            generated_by="t",
            parameters={"recipients": ["ops@example.com", "https://hooks.example/report"]},
            actor_roles=("analytics:analyst",),
        )
    )
    assert dto.status == "Complete"
    audit = c.delivery_audit.list_for_tenant(tid)
    assert len(audit) >= 2
    channels = {a["channel"] for a in audit}
    assert "email" in channels
    assert "webhook" in channels


@pytest.mark.asyncio
async def test_bi_export_rate_limit_raises() -> None:
    c = ReportingContainer()
    tid = uuid4()
    assert isinstance(c.bi_export_port, object)
    c.bi_export_port.seed(tid, "kpis", [{"v": i} for i in range(5)])  # type: ignore[attr-defined]
    for _ in range(10):
        await c.app.bi_export_page(tid, "kpis", ("analytics:analyst",), page=1, page_size=2)
    with pytest.raises(ApplicationRateLimitedError):
        await c.app.bi_export_page(tid, "kpis", ("analytics:analyst",), page=1, page_size=2)


@pytest.mark.asyncio
async def test_predictive_template_end_to_end_cold_start() -> None:
    ml = StubMLSignalQueryAdapter()
    c = ReportingContainer(ml_port=ml)
    tid = EntityId.generate()
    template_id = c.template_id_for(ReportType.PREDICTIVE_THREAT_FORECAST)
    assert template_id
    dto = await c.app.generate_on_demand(
        GenerateReportOnDemandCommand(
            tenant_id=tid,
            template_id=UUID(template_id),
            generated_by="t",
            parameters={
                "fallback_techniques": [
                    {"technique_id": "T9999", "cvss": 8.0, "exposure_score": 3.0}
                ]
            },
            actor_roles=("analytics:analyst",),
        )
    )
    assert dto.report_type == "PredictiveThreatForecast"
    assert dto.content["forecast_source"] == "rule_based_fallback"

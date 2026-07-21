"""Unit: template-driven report narrative for Phase 2 + Phase 4 templates."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from reporting.domain.aggregates.report_template import ReportTemplate
from reporting.domain.ports.i_analytics_kpi_query_port import (
    AnalyticsKPIBundleDTO,
    AnomalySnapshotDTO,
    KPISnapshotDTO,
)
from reporting.domain.services.report_generation_service import (
    ALL_NARRATIVE_VARIANTS,
    PHASE2_REPORT_TYPES,
    PHASE4_REPORT_TYPES,
    SUPPORTED_REPORT_TYPES,
    ReportGenerationService,
    compute_dominant_kpi_pattern,
    render_narrative,
    select_narrative_variant,
)
from reporting.domain.value_objects.enums import (
    NarrativeVariantId,
    ReportTrigger,
    ReportType,
)
from reporting.domain.value_objects.identifiers import ReportTemplateId, TenantId


def test_seven_platform_report_types() -> None:
    assert len(PHASE2_REPORT_TYPES) == 4
    assert len(PHASE4_REPORT_TYPES) == 3
    assert len(SUPPORTED_REPORT_TYPES) == 7
    assert ReportType.PREDICTIVE_THREAT_FORECAST in PHASE4_REPORT_TYPES
    assert ReportType.DETECTION_ANALYTICS_REPORT in PHASE4_REPORT_TYPES
    assert ReportType.CAMPAIGN_EFFECTIVENESS_REPORT in PHASE4_REPORT_TYPES


def test_dominant_kpi_pattern_selects_worst_trend() -> None:
    kpis = (
        KPISnapshotDTO("MTTD", 40.0, "m", 1.0, "Active"),
        KPISnapshotDTO("CoveragePct", 60.0, "%", 4.5, "Active"),
        KPISnapshotDTO("ExposureTrend", 2.0, "s", 0.2, "Active"),
    )
    assert compute_dominant_kpi_pattern(kpis) == "CoveragePct"
    assert select_narrative_variant("CoveragePct") == NarrativeVariantId.COVERAGE_GAP
    assert select_narrative_variant(None) == NarrativeVariantId.GENERAL_PROGRAM_PATTERN


def test_narrative_selection_for_all_four_templates() -> None:
    svc = ReportGenerationService()
    tenant = TenantId(uuid4())
    at = datetime(2026, 7, 21, tzinfo=UTC)
    bundle = AnalyticsKPIBundleDTO(
        kpis=(
            KPISnapshotDTO("MTTD", 90.0, "minutes", 5.0, "Active"),
            KPISnapshotDTO("CoveragePct", 70.0, "percent", 0.1, "Active"),
        ),
        anomalies=(AnomalySnapshotDTO("VulnerabilityIngestRate", "Warning", 12.0, 5.0),),
    )
    for report_type in PHASE2_REPORT_TYPES:
        template = ReportTemplate.create_platform(
            ReportTemplateId.generate(),
            report_type,
            report_type.value,
            ["section_a"],
            at,
        )
        instance = svc.build_instance(
            tenant_id=tenant,
            template=template,
            bundle=bundle,
            trigger=ReportTrigger.ON_DEMAND,
            generated_by="test",
            at=at,
        )
        assert instance.narrative_variant == NarrativeVariantId.MTTD_DEGRADATION.value
        assert "MTTD" in instance.narrative or "mttd" in instance.narrative.lower()
        assert instance.content["dominant_kpi_pattern"] == "MTTD"
        assert instance.content["report_type"] == report_type.value


def test_render_narrative_deterministic() -> None:
    slots = {
        "tenant_label": "t1",
        "mttd_value": 12.0,
        "coverage_value": 80.0,
        "exposure_value": 1.0,
        "campaign_value": 50.0,
        "ai_risk_value": 0.5,
        "dominant_delta": 2.0,
        "anomaly_count": 0,
        "generated_at": "2026-07-21T00:00:00+00:00",
        "forecast_source": "none",
    }
    a = render_narrative(
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.MTTD_DEGRADATION,
        slots,
    )
    b = render_narrative(
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.MTTD_DEGRADATION,
        slots,
    )
    assert a == b
    assert "12.0" in a
    assert len(ALL_NARRATIVE_VARIANTS) == 6

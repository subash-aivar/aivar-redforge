"""ReportGenerationService — template-driven narrative (ADR-M33-001; NO LLM)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from reporting.domain.aggregates.report_instance import ReportInstance
from reporting.domain.exceptions.domain_exceptions import UnsupportedReportType
from reporting.domain.value_objects.enums import (
    NarrativeVariantId,
    ReportTrigger,
    ReportType,
)
from reporting.domain.value_objects.identifiers import ReportInstanceId

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.aggregates.report_template import ReportTemplate
    from reporting.domain.ports.i_analytics_kpi_query_port import (
        AnalyticsKPIBundleDTO,
        KPISnapshotDTO,
    )
    from reporting.domain.ports.i_ml_signal_query_port import MLSignalBundleDTO
    from reporting.domain.value_objects.identifiers import (
        ScheduledReportId,
        TenantId,
    )

# Dominant KPI pattern → narrative variant (deterministic; no LLM).
_VARIANT_BY_KPI: dict[str, NarrativeVariantId] = {
    "MTTD": NarrativeVariantId.MTTD_DEGRADATION,
    "CoveragePct": NarrativeVariantId.COVERAGE_GAP,
    "ExposureTrend": NarrativeVariantId.EXPOSURE_WORSENING,
    "CampaignSuccessRate": NarrativeVariantId.CAMPAIGN_UNDERPERFORMANCE,
    "AIRiskTrend": NarrativeVariantId.AI_RISK_ELEVATION,
}

_REPORT_TITLE: dict[ReportType, str] = {
    ReportType.SECURITY_PROGRAM_DASHBOARD: "Security Program Dashboard",
    ReportType.EXECUTIVE_SECURITY_REPORT: "Executive Security Report",
    ReportType.KPI_TREND_REPORT: "KPI Trend Report",
    ReportType.ANOMALY_SUMMARY_REPORT: "Anomaly Summary Report",
    ReportType.DETECTION_ANALYTICS_REPORT: "Detection Analytics Report",
    ReportType.CAMPAIGN_EFFECTIVENESS_REPORT: "Campaign Effectiveness Report",
    ReportType.PREDICTIVE_THREAT_FORECAST: "Predictive Threat Forecast",
}

_NARRATIVE_BODIES: dict[tuple[ReportType, NarrativeVariantId], str] = {
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        NarrativeVariantId.MTTD_DEGRADATION,
    ): (
        "Security Program Dashboard: MTTD degradation dominates the KPI profile for "
        "{tenant_label}. Latest MTTD={mttd_value}; coverage={coverage_value}%. "
        "Focus detection latency remediation. Generated at {generated_at}."
    ),
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        NarrativeVariantId.COVERAGE_GAP,
    ): (
        "Security Program Dashboard: ATT&CK coverage gaps dominate. "
        "Coverage={coverage_value}%; MTTD={mttd_value}. Expand detection rules. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        NarrativeVariantId.EXPOSURE_WORSENING,
    ): (
        "Security Program Dashboard: Exposure trend worsening is dominant. "
        "Exposure trend={exposure_value}; campaign success={campaign_value}%. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        NarrativeVariantId.CAMPAIGN_UNDERPERFORMANCE,
    ): (
        "Security Program Dashboard: Campaign success underperformance dominates. "
        "Success rate={campaign_value}%. Rebalance red-team objectives. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        NarrativeVariantId.AI_RISK_ELEVATION,
    ): (
        "Security Program Dashboard: AI risk elevation dominates. "
        "AI risk trend={ai_risk_value}. Strengthen AI posture controls. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.SECURITY_PROGRAM_DASHBOARD,
        NarrativeVariantId.GENERAL_PROGRAM_PATTERN,
    ): (
        "Security Program Dashboard: No single KPI dominates. "
        "MTTD={mttd_value}; coverage={coverage_value}%; exposure={exposure_value}. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.MTTD_DEGRADATION,
    ): (
        "Executive Security Report: Program effectiveness is constrained by MTTD "
        "degradation (value={mttd_value}). Coverage={coverage_value}%; "
        "campaign success={campaign_value}%. Generated at {generated_at}."
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.COVERAGE_GAP,
    ): (
        "Executive Security Report: Coverage shortfalls limit program maturity. "
        "Coverage={coverage_value}%; MTTD={mttd_value}; AI risk={ai_risk_value}. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.EXPOSURE_WORSENING,
    ): (
        "Executive Security Report: Exposure trend is the dominant program risk. "
        "Exposure={exposure_value}; coverage={coverage_value}%. Generated at {generated_at}."
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.CAMPAIGN_UNDERPERFORMANCE,
    ): (
        "Executive Security Report: Campaign effectiveness lags targets "
        "(success={campaign_value}%). Align adversary emulation with critical assets. "
        "Generated at {generated_at}."
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.AI_RISK_ELEVATION,
    ): (
        "Executive Security Report: AI risk trend elevation requires board attention "
        "(AI risk={ai_risk_value}). Generated at {generated_at}."
    ),
    (
        ReportType.EXECUTIVE_SECURITY_REPORT,
        NarrativeVariantId.GENERAL_PROGRAM_PATTERN,
    ): (
        "Executive Security Report: Balanced KPI profile across MTTD={mttd_value}, "
        "coverage={coverage_value}%, exposure={exposure_value}. Generated at {generated_at}."
    ),
    (
        ReportType.KPI_TREND_REPORT,
        NarrativeVariantId.MTTD_DEGRADATION,
    ): (
        "KPI Trend Report: Worst trend is MTTD (delta={dominant_delta:.2f}, "
        "value={mttd_value}). Generated at {generated_at}."
    ),
    (
        ReportType.KPI_TREND_REPORT,
        NarrativeVariantId.COVERAGE_GAP,
    ): (
        "KPI Trend Report: Worst trend is CoveragePct (delta={dominant_delta:.2f}, "
        "value={coverage_value}%). Generated at {generated_at}."
    ),
    (
        ReportType.KPI_TREND_REPORT,
        NarrativeVariantId.EXPOSURE_WORSENING,
    ): (
        "KPI Trend Report: Worst trend is ExposureTrend (delta={dominant_delta:.2f}, "
        "value={exposure_value}). Generated at {generated_at}."
    ),
    (
        ReportType.KPI_TREND_REPORT,
        NarrativeVariantId.CAMPAIGN_UNDERPERFORMANCE,
    ): (
        "KPI Trend Report: Worst trend is CampaignSuccessRate "
        "(delta={dominant_delta:.2f}, value={campaign_value}%). Generated at {generated_at}."
    ),
    (
        ReportType.KPI_TREND_REPORT,
        NarrativeVariantId.AI_RISK_ELEVATION,
    ): (
        "KPI Trend Report: Worst trend is AIRiskTrend (delta={dominant_delta:.2f}, "
        "value={ai_risk_value}). Generated at {generated_at}."
    ),
    (
        ReportType.KPI_TREND_REPORT,
        NarrativeVariantId.GENERAL_PROGRAM_PATTERN,
    ): ("KPI Trend Report: No adverse KPI trend dominates. Snapshot at {generated_at}."),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        NarrativeVariantId.MTTD_DEGRADATION,
    ): (
        "Anomaly Summary Report: {anomaly_count} anomalies observed; MTTD pattern "
        "is dominant ({mttd_value}). Generated at {generated_at}."
    ),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        NarrativeVariantId.COVERAGE_GAP,
    ): (
        "Anomaly Summary Report: {anomaly_count} anomalies; coverage-gap pattern "
        "dominates (coverage={coverage_value}%). Generated at {generated_at}."
    ),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        NarrativeVariantId.EXPOSURE_WORSENING,
    ): (
        "Anomaly Summary Report: {anomaly_count} anomalies; exposure-worsening "
        "pattern dominates. Generated at {generated_at}."
    ),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        NarrativeVariantId.CAMPAIGN_UNDERPERFORMANCE,
    ): (
        "Anomaly Summary Report: {anomaly_count} anomalies; campaign "
        "underperformance pattern dominates. Generated at {generated_at}."
    ),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        NarrativeVariantId.AI_RISK_ELEVATION,
    ): (
        "Anomaly Summary Report: {anomaly_count} anomalies; AI risk elevation "
        "pattern dominates. Generated at {generated_at}."
    ),
    (
        ReportType.ANOMALY_SUMMARY_REPORT,
        NarrativeVariantId.GENERAL_PROGRAM_PATTERN,
    ): (
        "Anomaly Summary Report: {anomaly_count} anomalies with no dominant KPI "
        "pattern. Generated at {generated_at}."
    ),
}

SUPPORTED_REPORT_TYPES: tuple[ReportType, ...] = tuple(ReportType)
PHASE2_REPORT_TYPES: tuple[ReportType, ...] = (
    ReportType.SECURITY_PROGRAM_DASHBOARD,
    ReportType.EXECUTIVE_SECURITY_REPORT,
    ReportType.KPI_TREND_REPORT,
    ReportType.ANOMALY_SUMMARY_REPORT,
)
PHASE4_REPORT_TYPES: tuple[ReportType, ...] = (
    ReportType.DETECTION_ANALYTICS_REPORT,
    ReportType.CAMPAIGN_EFFECTIVENESS_REPORT,
    ReportType.PREDICTIVE_THREAT_FORECAST,
)
ALL_NARRATIVE_VARIANTS: tuple[NarrativeVariantId, ...] = tuple(NarrativeVariantId)

# Phase 4 narrative bodies (GENERAL variant; dominant KPI still selects variant key)
for _rt, _intro in (
    (
        ReportType.DETECTION_ANALYTICS_REPORT,
        "Detection Analytics Report: ATT&CK coverage and FP-rate trends for {tenant_label}. "
        "Coverage={coverage_value}%; anomalies={anomaly_count}. Generated at {generated_at}.",
    ),
    (
        ReportType.CAMPAIGN_EFFECTIVENESS_REPORT,
        "Campaign Effectiveness Report: success-rate trends for {tenant_label}. "
        "Campaign success={campaign_value}%. Generated at {generated_at}.",
    ),
    (
        ReportType.PREDICTIVE_THREAT_FORECAST,
        "Predictive Threat Forecast: top exploitation-risk techniques for {tenant_label}. "
        "Source={forecast_source}. Generated at {generated_at}.",
    ),
):
    for _variant in NarrativeVariantId:
        _NARRATIVE_BODIES[(_rt, _variant)] = _intro


def compute_dominant_kpi_pattern(kpis: tuple[KPISnapshotDTO, ...]) -> str | None:
    """Dominant = highest trend_delta (worst KPI trend)."""
    if not kpis:
        return None
    ranked = [k for k in kpis if k.value is not None]
    if not ranked:
        return None
    return max(ranked, key=lambda k: k.trend_delta).kpi_type


def select_narrative_variant(dominant_kpi_type: str | None) -> NarrativeVariantId:
    if dominant_kpi_type is None:
        return NarrativeVariantId.GENERAL_PROGRAM_PATTERN
    return _VARIANT_BY_KPI.get(dominant_kpi_type, NarrativeVariantId.GENERAL_PROGRAM_PATTERN)


def render_narrative(
    report_type: ReportType,
    variant: NarrativeVariantId,
    slots: dict[str, object],
) -> str:
    key = (report_type, variant)
    body = (
        _NARRATIVE_BODIES.get(key)
        or _NARRATIVE_BODIES[(report_type, NarrativeVariantId.GENERAL_PROGRAM_PATTERN)]
    )
    return body.format(**slots)


def _kpi_value_map(kpis: tuple[KPISnapshotDTO, ...]) -> dict[str, float | None]:
    return {k.kpi_type: k.value for k in kpis}


class ReportGenerationService:
    """Domain service: build ReportInstance from template + KPI bundle (no LLM)."""

    def build_instance(
        self,
        *,
        tenant_id: TenantId,
        template: ReportTemplate,
        bundle: AnalyticsKPIBundleDTO,
        trigger: ReportTrigger,
        generated_by: str,
        at: datetime,
        schedule_id: ScheduledReportId | None = None,
        parameters: dict[str, Any] | None = None,
        ml_bundle: MLSignalBundleDTO | None = None,
    ) -> ReportInstance:
        report_type = template.report_type
        if report_type not in SUPPORTED_REPORT_TYPES:
            raise UnsupportedReportType(report_type.value)

        dominant = compute_dominant_kpi_pattern(bundle.kpis)
        variant = select_narrative_variant(dominant)
        values = _kpi_value_map(bundle.kpis)
        dominant_delta = 0.0
        for kpi in bundle.kpis:
            if kpi.kpi_type == dominant:
                dominant_delta = kpi.trend_delta
                break

        forecast_source = "none"
        top_techniques: list[dict[str, Any]] = []
        if report_type == ReportType.PREDICTIVE_THREAT_FORECAST:
            top_techniques, forecast_source = self.select_top_techniques(
                ml_bundle, parameters or {}
            )

        slots: dict[str, object] = {
            "tenant_label": str(tenant_id),
            "mttd_value": values.get("MTTD", "n/a"),
            "coverage_value": values.get("CoveragePct", "n/a"),
            "exposure_value": values.get("ExposureTrend", "n/a"),
            "campaign_value": values.get("CampaignSuccessRate", "n/a"),
            "ai_risk_value": values.get("AIRiskTrend", "n/a"),
            "dominant_delta": dominant_delta,
            "anomaly_count": len(bundle.anomalies),
            "generated_at": at.isoformat(),
            "forecast_source": forecast_source,
        }
        narrative = render_narrative(report_type, variant, slots)
        content = self._build_content(
            report_type=report_type,
            template=template,
            bundle=bundle,
            dominant=dominant,
            variant=variant,
            parameters=parameters or {},
            top_techniques=top_techniques,
            forecast_source=forecast_source,
        )
        instance = ReportInstance.start(
            ReportInstanceId.generate(),
            tenant_id,
            template.template_id,
            report_type,
            trigger,
            generated_by,
            at,
            schedule_id=schedule_id,
        )
        artifact_ref = f"reporting://{tenant_id}/{instance.instance_id}"
        instance.complete(
            tenant_id,
            narrative=narrative,
            narrative_variant=variant.value,
            content=content,
            artifact_ref=artifact_ref,
            at=at,
        )
        return instance

    def select_top_techniques(
        self,
        ml_bundle: MLSignalBundleDTO | None,
        parameters: dict[str, Any],
        *,
        top_n: int = 5,
    ) -> tuple[list[dict[str, Any]], str]:
        """ML top-N by exploitation probability; cold start → CVSS+exposure fallback."""
        if ml_bundle is not None and ml_bundle.model_deployed and ml_bundle.signals:
            ranked = sorted(
                ml_bundle.signals,
                key=lambda s: float(
                    s.exploitation_probability
                    if s.exploitation_probability is not None
                    else s.score
                ),
                reverse=True,
            )[:top_n]
            return (
                [
                    {
                        "technique_id": s.technique_id or s.asset_ref_id,
                        "score": float(
                            s.exploitation_probability
                            if s.exploitation_probability is not None
                            else s.score
                        ),
                        "source": "ml_predictive_risk_signal",
                    }
                    for s in ranked
                ],
                "ml_model",
            )
        # Rule-based fallback: CVSS + exposure from parameters
        candidates = parameters.get("fallback_techniques")
        if isinstance(candidates, list) and candidates:
            scored: list[dict[str, Any]] = []
            for c in candidates:
                if not isinstance(c, dict):
                    continue
                cvss = float(c.get("cvss", 0.0))
                exposure = float(c.get("exposure_score", 0.0))
                scored.append(
                    {
                        "technique_id": str(c.get("technique_id", "unknown")),
                        "score": cvss + exposure,
                        "source": "rule_based_cvss_exposure",
                    }
                )
            scored.sort(key=lambda r: float(r["score"]), reverse=True)
            return scored[:top_n], "rule_based_fallback"
        return [], "cold_start_empty"

    def _build_content(
        self,
        *,
        report_type: ReportType,
        template: ReportTemplate,
        bundle: AnalyticsKPIBundleDTO,
        dominant: str | None,
        variant: NarrativeVariantId,
        parameters: dict[str, Any],
        top_techniques: list[dict[str, Any]] | None = None,
        forecast_source: str = "none",
    ) -> dict[str, Any]:
        base: dict[str, Any] = {
            "title": _REPORT_TITLE[report_type],
            "report_type": report_type.value,
            "template": template.to_definition(),
            "dominant_kpi_pattern": dominant,
            "narrative_variant": variant.value,
            "sections": list(template.sections),
            "kpis": [
                {
                    "kpi_type": k.kpi_type,
                    "value": k.value,
                    "unit": k.unit,
                    "trend_delta": k.trend_delta,
                    "status": k.status,
                }
                for k in bundle.kpis
            ],
            "anomalies": [
                {
                    "signal_type": a.signal_type,
                    "severity": a.severity,
                    "observed_value": a.observed_value,
                    "threshold": a.threshold,
                }
                for a in bundle.anomalies
            ],
            "parameters": dict(parameters),
        }
        if report_type == ReportType.SECURITY_PROGRAM_DASHBOARD:
            base["dashboard"] = True
        elif report_type == ReportType.EXECUTIVE_SECURITY_REPORT:
            base["executive_summary"] = True
        elif report_type == ReportType.KPI_TREND_REPORT:
            base["trend_focus"] = dominant
        elif report_type == ReportType.ANOMALY_SUMMARY_REPORT:
            base["anomaly_focus"] = True
        elif report_type == ReportType.DETECTION_ANALYTICS_REPORT:
            base["detection_analytics"] = {
                "attck_coverage": parameters.get("attck_coverage"),
                "fp_rate_trend": parameters.get("fp_rate_trend"),
                "top_coverage_gaps": parameters.get("top_coverage_gaps", []),
            }
        elif report_type == ReportType.CAMPAIGN_EFFECTIVENESS_REPORT:
            base["campaign_effectiveness"] = {
                "success_rate_trend": parameters.get("success_rate_trend"),
                "technique_coverage_delta": parameters.get("technique_coverage_delta"),
            }
        elif report_type == ReportType.PREDICTIVE_THREAT_FORECAST:
            base["top_techniques"] = list(top_techniques or [])
            base["forecast_source"] = forecast_source
        return base

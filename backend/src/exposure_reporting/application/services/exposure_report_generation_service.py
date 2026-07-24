"""ExposureReportGenerationService — template selection + substitution (Phase 5)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from exposure_reporting.application._auth import require_at_least
from exposure_reporting.application.dtos.reporting_dtos import ExposureReportDTO
from exposure_reporting.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from exposure_reporting.domain.aggregates.exposure_report import ExposureReport
from exposure_reporting.domain.events.reporting_events import (
    ExposureGraphEdgeUpserted,
    ExposureGraphNodeUpserted,
)
from exposure_reporting.domain.exceptions.domain_exceptions import (
    ExposureReportingDomainError,
)
from exposure_reporting.domain.services.narrative_template_service import (
    compute_dominant_amplifier,
    render_narrative,
    select_template,
)
from exposure_reporting.domain.value_objects.enums import ReportingRole, ReportType
from exposure_reporting.domain.value_objects.identifiers import (
    ExposureReportId,
    TenantId,
)

if TYPE_CHECKING:
    from uuid import UUID

    from exposure_reporting.application.commands.reporting_commands import (
        DeliverExposureReportCommand,
        GenerateExposureReportCommand,
    )
    from exposure_reporting.application.ports.i_event_publisher import IEventPublisher
    from exposure_reporting.application.ports.i_exposure_data_query_port import (
        IExposureDataQueryPort,
    )
    from exposure_reporting.domain.ports.i_security_graph_write_port import (
        ISecurityGraphWritePort,
    )
    from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
        IBusinessImpactMappingRepository,
    )
    from exposure_reporting.domain.repositories.i_exposure_report_repository import (
        IExposureReportRepository,
    )


def _to_dto(report: ExposureReport, freshness_warning: bool = False) -> ExposureReportDTO:
    return ExposureReportDTO(
        report_id=str(report.report_id),
        tenant_id=str(report.tenant_id),
        report_type=report.report_type.value,
        status=report.status.value,
        template_id=report.template_id,
        narrative=report.narrative,
        content=dict(report.content),
        generated_by=report.generated_by,
        generated_at=report.generated_at.isoformat(),
        time_range_start=(report.time_range_start.isoformat() if report.time_range_start else None),
        time_range_end=report.time_range_end.isoformat() if report.time_range_end else None,
        delivered_at=report.delivered_at.isoformat() if report.delivered_at else None,
        data_freshness_warning=freshness_warning
        or bool(report.content.get("data_freshness_warning", False)),
    )


class ExposureReportGenerationService:
    def __init__(
        self,
        report_repo: IExposureReportRepository,
        mapping_repo: IBusinessImpactMappingRepository,
        exposure_port: IExposureDataQueryPort,
        graph_port: ISecurityGraphWritePort,
        event_publisher: IEventPublisher,
    ) -> None:
        self._reports = report_repo
        self._mappings = mapping_repo
        self._exposure = exposure_port
        self._graph = graph_port
        self._events = event_publisher

    async def generate(self, cmd: GenerateExposureReportCommand) -> ExposureReportDTO:
        require_at_least(cmd.actor_roles, ReportingRole.ANALYST)
        try:
            report_type = ReportType(cmd.report_type)
        except ValueError as exc:
            raise ApplicationValidationError(f"unknown report_type: {cmd.report_type}") from exc
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        snap = await self._exposure.load_snapshot(cmd.tenant_id)
        dominant = compute_dominant_amplifier(dict(snap.amplifier_weight_prevalence))
        template = select_template(dominant)
        asset_count = len(snap.asset_scores)
        tenant_score = sum(snap.asset_scores.values()) / asset_count if asset_count else 0.0
        mappings = await self._mappings.list_by_tenant(tenant)
        mapped = {str(m.asset_ref_id): m.criticality.value for m in mappings}
        narrative = render_narrative(
            template,
            {
                "tenant_label": str(cmd.tenant_id),
                "tenant_score": tenant_score,
                "asset_count": asset_count,
                "generated_at": now.isoformat(),
            },
        )
        frameworks = sorted({reg for m in mappings for reg in m.regulatory_scope})
        content = self._build_content(
            report_type=report_type,
            snap=snap,
            dominant=dominant,
            tenant_score=tenant_score,
            mapped=mapped,
            narrative_template=template.value,
            frameworks=frameworks,
        )
        report = ExposureReport.create(
            ExposureReportId.generate(),
            tenant,
            report_type,
            template.value,
            narrative,
            content,
            cmd.generated_by,
            now,
            time_range_start=cmd.time_range_start,
            time_range_end=cmd.time_range_end,
        )
        await self._reports.save(tenant, report)
        await self._events.publish_batch(report.pop_events())
        await self._project_graph(tenant, report, snap.asset_scores)
        return _to_dto(report, freshness_warning=snap.threat_cache_stale)

    def _build_content(
        self,
        *,
        report_type: ReportType,
        snap: Any,
        dominant: str | None,
        tenant_score: float,
        mapped: dict[str, str],
        narrative_template: str,
        frameworks: list[str],
    ) -> dict[str, Any]:
        top_assets = sorted(snap.asset_scores.items(), key=lambda kv: kv[1], reverse=True)[:25]
        base: dict[str, Any] = {
            "dominant_amplifier": dominant,
            "narrative_template": narrative_template,
            "tenant_exposure_score": tenant_score,
            "asset_count": len(snap.asset_scores),
            "score_input_version": snap.score_input_version,
            "data_freshness_warning": snap.threat_cache_stale,
            "top_assets": [
                {
                    "asset_ref_id": aid,
                    "exposure_score": score,
                    "business_criticality": mapped.get(aid),
                    "business_impact_mapped": aid in mapped,
                }
                for aid, score in top_assets
            ],
            "mapped_asset_count": len(mapped),
            "unmapped_asset_count": max(0, len(snap.asset_scores) - len(mapped)),
        }
        if report_type == ReportType.BOARD_RISK_SUMMARY:
            base["executive_kpis"] = {
                "tenant_exposure_score": tenant_score,
                "critical_asset_exposure": sum(
                    s
                    for a, s in snap.asset_scores.items()
                    if mapped.get(a) in {"MissionCritical", "High"}
                ),
            }
        elif report_type == ReportType.REMEDIATION_ROADMAP:
            base["roadmap"] = [
                {
                    "priority": idx + 1,
                    "asset_ref_id": aid,
                    "exposure_score": score,
                    "recommended_action": "Remediate dominant amplifiers",
                }
                for idx, (aid, score) in enumerate(top_assets[:10])
            ]
        elif report_type == ReportType.COMPLIANCE_GAP_REPORT:
            base["compliance_summary"] = {
                "assets_without_business_impact": [a for a in snap.asset_scores if a not in mapped][
                    :50
                ],
                "frameworks_in_scope": frameworks,
            }
        elif report_type == ReportType.EXPOSURE_SCORE_TREND:
            base["trend_points"] = [
                {
                    "asset_ref_id": p.asset_ref_id,
                    "composite_score": p.composite_score,
                    "computed_at": p.computed_at,
                }
                for p in snap.snapshot_history
            ]
        elif report_type == ReportType.TENANT_EXPOSURE_DASHBOARD:
            base["dashboard"] = True
        return base

    async def _project_graph(
        self,
        tenant: TenantId,
        report: ExposureReport,
        asset_scores: dict[str, float],
    ) -> None:
        node_event_id = str(uuid4())
        await self._graph.upsert_exposure_node(
            tenant_id=str(tenant),
            node_type="ExposureReport",
            node_key=str(report.report_id),
            properties={
                "report_type": report.report_type.value,
                "template_id": report.template_id,
                "generated_at": report.generated_at.isoformat(),
            },
            event_id=node_event_id,
        )
        await self._events.publish_batch(
            [
                ExposureGraphNodeUpserted(
                    tenant_id=str(tenant),
                    aggregate_id=str(report.report_id),
                    node_type="ExposureReport",
                    node_key=str(report.report_id),
                )
            ]
        )
        for asset_id, score in list(asset_scores.items())[:100]:
            edge_id = str(uuid4())
            await self._graph.upsert_exposure_edge(
                tenant_id=str(tenant),
                edge_type="ReportIncludesAsset",
                from_key=str(report.report_id),
                to_key=asset_id,
                properties={"exposure_score": score},
                event_id=edge_id,
            )
            await self._events.publish_batch(
                [
                    ExposureGraphEdgeUpserted(
                        tenant_id=str(tenant),
                        aggregate_id=str(report.report_id),
                        edge_type="ReportIncludesAsset",
                        from_key=str(report.report_id),
                        to_key=asset_id,
                    )
                ]
            )

    async def deliver(self, cmd: DeliverExposureReportCommand) -> ExposureReportDTO:
        require_at_least(cmd.actor_roles, ReportingRole.ANALYST)
        tenant = cmd.tenant_id
        report = await self._reports.get(tenant, ExposureReportId(cmd.report_id))
        if report is None:
            raise ApplicationNotFoundError(str(cmd.report_id))
        try:
            report.mark_delivered(tenant, cmd.delivery_channel, datetime.now(UTC))
        except ExposureReportingDomainError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        await self._reports.save(tenant, report)
        await self._events.publish_batch(report.pop_events())
        return _to_dto(report)

    async def get(
        self, tenant_id: TenantId, report_id: UUID, actor_roles: tuple[str, ...]
    ) -> ExposureReportDTO:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        report = await self._reports.get(tenant_id, ExposureReportId(report_id))
        if report is None:
            raise ApplicationNotFoundError(str(report_id))
        return _to_dto(report)

    async def list_reports(
        self,
        tenant_id: TenantId,
        actor_roles: tuple[str, ...],
        *,
        report_type: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> list[ExposureReportDTO]:
        require_at_least(actor_roles, ReportingRole.VIEWER)
        rows = await self._reports.list_by_tenant(
            tenant_id,
            report_type=report_type,
            from_dt=from_dt,
            to_dt=to_dt,
        )
        return [_to_dto(r) for r in rows]

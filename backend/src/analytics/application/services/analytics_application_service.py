"""Application services for analytics Phase 1 + Phase 2."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from analytics.application._auth import require_at_least
from analytics.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from analytics.domain.aggregates.analytics_dataset import AnalyticsDataSet
from analytics.domain.aggregates.analytics_query import AnalyticsQuery
from analytics.domain.aggregates.anomaly_detection_baseline import (
    AnomalyDetectionBaseline,
)
from analytics.domain.aggregates.security_kpi import SecurityKPI
from analytics.domain.exceptions.domain_exceptions import AnalyticsQueryValidationError
from analytics.domain.services.analytics_query_validation_service import (
    MAX_ROWS_ABSOLUTE,
    AnalyticsQueryValidationService,
)
from analytics.domain.services.anomaly_detection_service import AnomalyDetectionService
from analytics.domain.services.kpi_computation_service import KPIComputationService
from analytics.domain.value_objects.enums import (
    AnalyticsRole,
    AnomalySignalType,
    DetectionMethod,
    KPIType,
    SecurityDomain,
)
from analytics.domain.value_objects.identifiers import (
    AnalyticsDataSetId,
    AnalyticsQueryId,
    AnomalyDetectionBaselineId,
    QueryExecutionId,
    SecurityKPIId,
    TenantId,
)

if TYPE_CHECKING:
    from uuid import UUID

    from analytics.application.commands.analytics_commands import (
        CreateAnalyticsQueryCommand,
        CreateAnomalyBaselineCommand,
        DefineSecurityKPICommand,
        ExecuteAnalyticsQueryCommand,
        IngestAnalyticsEventCommand,
        RegisterAnalyticsDataSetCommand,
        TriggerKPIComputationCommand,
        TriggerProjectionRebuildCommand,
    )
    from analytics.application.ports.i_event_publisher import IEventPublisher
    from analytics.infrastructure.persistence.in_memory_repositories import (
        InMemoryAnalyticsDataSetRepository,
        InMemoryAnalyticsQueryRepository,
        InMemoryAnomalyDetectionBaselineRepository,
        InMemorySecurityKPIRepository,
    )
    from analytics.infrastructure.projections.event_projection_store import (
        EventProjectionStore,
    )


class AnalyticsApplicationService:
    def __init__(
        self,
        datasets: InMemoryAnalyticsDataSetRepository,
        kpis: InMemorySecurityKPIRepository,
        baselines: InMemoryAnomalyDetectionBaselineRepository,
        queries: InMemoryAnalyticsQueryRepository,
        store: EventProjectionStore,
        events: IEventPublisher,
        *,
        attck_techniques: set[str] | None = None,
        graph_port: Any | None = None,
        ml_anomaly_port: Any | None = None,
        metrics: Any | None = None,
        settings: Any | None = None,
    ) -> None:
        self._datasets = datasets
        self._kpis = kpis
        self._baselines = baselines
        self._queries = queries
        self._store = store
        self._events = events
        self._graph = graph_port
        self._ml_anomaly = ml_anomaly_port
        self._metrics = metrics
        self._settings = settings
        self._kpi_engine = KPIComputationService()
        self._anomaly_engine = AnomalyDetectionService()
        self._query_validator = AnalyticsQueryValidationService()
        self._attck = attck_techniques or {f"T{i:04d}" for i in range(1000, 1050)}
        self._query_results: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []

    async def register_dataset(self, cmd: RegisterAnalyticsDataSetCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        try:
            domain = SecurityDomain(cmd.domain)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        ds = AnalyticsDataSet.register(
            AnalyticsDataSetId.generate(), tenant, domain, cmd.schema_version, now
        )
        await self._datasets.save(tenant, ds)
        await self._events.publish_batch(ds.pop_events())
        return {
            "dataset_id": str(ds.dataset_id),
            "domain": ds.domain.value,
            "status": ds.status.value,
            "schema_version": ds.schema_version,
        }

    async def define_kpi(self, cmd: DefineSecurityKPICommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        try:
            kpi_type = KPIType(cmd.kpi_type)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        tenant = TenantId(cmd.tenant_id)
        existing = await self._kpis.find_by_type(tenant, kpi_type)
        if existing is not None:
            return {
                "kpi_id": str(existing.kpi_id),
                "kpi_type": existing.kpi_type.value,
                "status": existing.status.value,
            }
        kpi = SecurityKPI.define(
            SecurityKPIId.generate(),
            tenant,
            kpi_type,
            cmd.computation_schedule,
            datetime.now(UTC),
        )
        await self._kpis.save(tenant, kpi)
        return {
            "kpi_id": str(kpi.kpi_id),
            "kpi_type": kpi.kpi_type.value,
            "status": kpi.status.value,
            "schedule": kpi.computation_schedule_cron,
        }

    async def create_baseline(self, cmd: CreateAnomalyBaselineCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        try:
            signal = AnomalySignalType(cmd.signal_type)
            method = DetectionMethod(cmd.method)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        baseline = AnomalyDetectionBaseline.create(
            AnomalyDetectionBaselineId.generate(),
            tenant,
            signal,
            method,
            cmd.window_days,
            now,
        )
        # Bootstrap from vulnerability ingest rates if available
        values = self._signal_series(cmd.tenant_id, signal)
        baseline.bootstrap(tenant, values=values, at=now)
        await self._baselines.save(tenant, baseline)
        return {
            "baseline_id": str(baseline.baseline_id),
            "signal_type": baseline.signal_type.value,
            "method": baseline.method.value,
            "bootstrapped": baseline.bootstrapped,
            "observation_count": baseline.observation_count,
        }

    def _signal_series(self, tenant_id: UUID, signal: AnomalySignalType) -> list[float]:
        # Simplified daily counts for bootstrap
        if signal == AnomalySignalType.VULNERABILITY_INGEST_RATE:
            rows = self._store.list_events(tenant_id, "vulnerability")
            return [float(i + 1) for i in range(min(30, max(0, len(rows))))] or [
                float(x) for x in range(1, 20)
            ]
        return [float(x) for x in range(1, 20)]

    async def ingest_event(self, cmd: IngestAnalyticsEventCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        domain_map = {
            "Vulnerability": "vulnerability",
            "Detection": "detection",
            "RedTeam": "execution",
            "Campaign": "campaign",
            "Exposure": "exposure",
            "AIPosture": "ai_posture",
        }
        domain = domain_map.get(cmd.domain, cmd.domain.lower())
        inserted = self._store.ingest(
            cmd.tenant_id,
            domain=domain,
            event_id=cmd.event_id,
            event_type=cmd.event_type,
            event_ts=cmd.event_ts,
            payload=dict(cmd.payload),
        )
        if inserted:
            tenant = TenantId(cmd.tenant_id)
            try:
                sec_domain = SecurityDomain(cmd.domain)
            except ValueError:
                sec_domain = SecurityDomain.CROSS_DOMAIN
            datasets = await self._datasets.find_by_domain(tenant, sec_domain)
            for ds in datasets:
                ds.advance_checkpoint(tenant, cmd.event_id, datetime.now(UTC), ingested=1)
                await self._datasets.save(tenant, ds)
                await self._events.publish_batch(ds.pop_events())
        return {"ingested": inserted, "event_id": cmd.event_id}

    async def trigger_kpi(self, cmd: TriggerKPIComputationCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ADMIN)
        try:
            kpi_type = KPIType(cmd.kpi_type)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        tenant = TenantId(cmd.tenant_id)
        kpi = await self._kpis.find_by_type(tenant, kpi_type)
        if kpi is None:
            kpi = SecurityKPI.define(
                SecurityKPIId.generate(),
                tenant,
                kpi_type,
                "0 2 * * *",
                datetime.now(UTC),
            )
        events = self._store.all_domain_events(cmd.tenant_id)
        active_tech = {
            str(e.get("technique_id"))
            for e in events.get("detection", [])
            if e.get("technique_id")
            and e.get("event_type") in {"DetectionRuleActivated", "detection_rule_activated"}
        }
        result = self._kpi_engine.compute(
            kpi_type,
            tenant_id=cmd.tenant_id,
            events=events,
            attck_total=len(self._attck),
            active_technique_ids=active_tech,
        )
        now = datetime.now(UTC)
        kpi.record_computation(
            tenant,
            value=result.value,
            unit=result.unit,
            status=result.status,
            at=now,
        )
        await self._kpis.save(tenant, kpi)
        await self._events.publish_batch(kpi.pop_events())
        self._store.append_kpi_snapshot(
            cmd.tenant_id,
            {
                "kpi_type": kpi_type.value,
                "value": result.value,
                "unit": result.unit,
                "status": result.status.value,
                "definition_version": result.definition_version,
                "snapshot_at": now.isoformat(),
            },
        )
        return {
            "kpi_type": kpi_type.value,
            "value": result.value,
            "unit": result.unit,
            "status": result.status.value,
        }

    async def trigger_rebuild(self, cmd: TriggerProjectionRebuildCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ADMIN)
        tenant = TenantId(cmd.tenant_id)
        active = await self._datasets.find_all_active(tenant)
        rebuilt = 0
        for ds in active:
            if cmd.domain and ds.domain.value != cmd.domain:
                continue
            domain_key = {
                SecurityDomain.VULNERABILITY: "vulnerability",
                SecurityDomain.DETECTION: "detection",
                SecurityDomain.RED_TEAM: "execution",
                SecurityDomain.CAMPAIGN: "campaign",
                SecurityDomain.EXPOSURE: "exposure",
                SecurityDomain.AI_POSTURE: "ai_posture",
            }.get(ds.domain, "vulnerability")
            now = datetime.now(UTC)
            ds.begin_rebuild(tenant, now)
            # Snapshot events, clear, re-ingest (idempotent replay simulation)
            existing = self._store.list_events(cmd.tenant_id, domain_key, include_archived=True)
            self._store.clear_domain(cmd.tenant_id, domain_key)
            # Clear processed set for those events to allow replay
            for row in existing:
                self._store.processed[str(cmd.tenant_id)].discard(str(row["event_id"]))
            for row in existing:
                self._store.ingest(
                    cmd.tenant_id,
                    domain=domain_key,
                    event_id=str(row["event_id"]),
                    event_type=str(row["event_type"]),
                    event_ts=row["event_ts"],
                    payload=dict(row.get("payload") or {}),
                )
            checkpoint = existing[-1]["event_id"] if existing else "empty"
            ds.complete_rebuild(tenant, str(checkpoint), now, len(existing))
            await self._datasets.save(tenant, ds)
            await self._events.publish_batch(ds.pop_events())
            rebuilt += 1
        return {"rebuilt_datasets": rebuilt}

    async def get_kpi(
        self, tenant_id: UUID, kpi_type: str, actor_roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        try:
            kt = KPIType(kpi_type)
        except ValueError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        kpi = await self._kpis.find_by_type(TenantId(tenant_id), kt)
        if kpi is None:
            raise ApplicationNotFoundError(kpi_type)
        history = self._store.list_kpi_snapshots(tenant_id, kt.value)
        return {
            "kpi_id": str(kpi.kpi_id),
            "kpi_type": kpi.kpi_type.value,
            "status": kpi.status.value,
            "latest_value": kpi.latest_value,
            "unit": kpi.latest_unit,
            "last_computed_at": (
                kpi.last_computed_at.isoformat() if kpi.last_computed_at else None
            ),
            "definition_version": kpi.definition_version,
            "history_count": len(history),
        }

    async def get_kpi_history(
        self, tenant_id: UUID, kpi_type: str, actor_roles: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        return self._store.list_kpi_snapshots(tenant_id, kpi_type)

    async def list_anomalies(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        return self._store.list_anomalies(tenant_id)

    async def get_dataset_status(
        self, tenant_id: UUID, dataset_id: UUID, actor_roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        ds = await self._datasets.find_by_id(TenantId(tenant_id), AnalyticsDataSetId(dataset_id))
        if ds is None:
            raise ApplicationNotFoundError(str(dataset_id))
        return {
            "dataset_id": str(ds.dataset_id),
            "domain": ds.domain.value,
            "status": ds.status.value,
            "checkpoint": ds.projection_checkpoint,
            "records_ingested": ds.records_ingested,
        }

    async def get_summary(self, tenant_id: UUID, actor_roles: tuple[str, ...]) -> dict[str, Any]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        tenant = TenantId(tenant_id)
        kpis = []
        for kt in KPIType:
            row = await self._kpis.find_by_type(tenant, kt)
            if row is not None:
                kpis.append(
                    {
                        "kpi_type": row.kpi_type.value,
                        "status": row.status.value,
                        "latest_value": row.latest_value,
                    }
                )
        return {
            "tenant_id": str(tenant_id),
            "kpis": kpis,
            "anomaly_count": len(self._store.list_anomalies(tenant_id)),
            "datasets": len(await self._datasets.find_all_active(tenant)),
        }

    async def evaluate_anomaly(
        self,
        tenant_id: UUID,
        signal_type: str,
        observed: float,
        actor_roles: tuple[str, ...],
    ) -> dict[str, Any]:
        require_at_least(actor_roles, AnalyticsRole.ANALYST)
        baseline = await self._baselines.find_by_signal_type(
            TenantId(tenant_id), AnomalySignalType(signal_type)
        )
        if baseline is None:
            raise ApplicationNotFoundError(signal_type)
        started = datetime.now(UTC)
        if baseline.method == DetectionMethod.ML_ISOLATION_FOREST:
            if self._ml_anomaly is None or (
                self._settings is not None and not self._settings.enable_ml_anomaly
            ):
                result = self._anomaly_engine.evaluate_from_ml_score(
                    anomaly_score=0.0, available=False
                )
            else:
                ml = await self._ml_anomaly.score(tenant_id, features=[observed, 0.0, 0.0, 0.0])
                result = self._anomaly_engine.evaluate_from_ml_score(
                    anomaly_score=ml.anomaly_score, available=ml.available
                )
        else:
            result = self._anomaly_engine.evaluate(baseline, observed)
        if result.is_anomaly:
            self._store.append_anomaly(
                tenant_id,
                {
                    "signal_type": signal_type,
                    "severity": result.severity.value,
                    "score": result.score,
                    "observed": observed,
                    "method": result.method.value,
                    "detected_at": datetime.now(UTC).isoformat(),
                },
            )
            if self._graph is not None and (
                self._settings is None or self._settings.enable_graph_anomaly_writes
            ):
                await self._graph.upsert_anomaly_node(
                    tenant_id,
                    signal_type=signal_type,
                    severity=result.severity.value,
                    score=result.score,
                    observed=observed,
                )
        if self._metrics is not None:
            elapsed_ms = (datetime.now(UTC) - started).total_seconds() * 1000.0
            self._metrics.record(
                "anomaly_evaluate_ms",
                elapsed_ms,
                unit="ms",
                tenant_id=tenant_id,
                labels={"signal_type": signal_type, "method": result.method.value},
            )
        return {
            "is_anomaly": result.is_anomaly,
            "score": result.score,
            "severity": result.severity.value,
            "bootstrapped": result.bootstrapped,
            "method": result.method.value,
        }

    # --- Phase 2 query API ---

    async def create_query(self, cmd: CreateAnalyticsQueryCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        try:
            domain = SecurityDomain(cmd.domain)
            self._query_validator.validate_template(cmd.template)
        except (ValueError, AnalyticsQueryValidationError) as exc:
            raise ApplicationValidationError(str(exc)) from exc
        if domain == SecurityDomain.CROSS_DOMAIN:
            require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        query = AnalyticsQuery.create(
            AnalyticsQueryId.generate(),
            tenant,
            cmd.name,
            cmd.template,
            domain,
            list(cmd.parameters),
            cmd.created_by,
            now,
        )
        await self._queries.save(tenant, query)
        await self._events.publish_batch(query.pop_events())
        return {
            "query_id": str(query.query_id),
            "name": query.name,
            "domain": query.domain.value,
        }

    async def execute_query(self, cmd: ExecuteAnalyticsQueryCommand) -> dict[str, Any]:
        require_at_least(cmd.actor_roles, AnalyticsRole.ANALYST)
        tenant = TenantId(cmd.tenant_id)
        query = await self._queries.find_by_id(tenant, AnalyticsQueryId(cmd.query_id))
        if query is None:
            raise ApplicationNotFoundError(str(cmd.query_id))
        if query.domain == SecurityDomain.CROSS_DOMAIN:
            require_at_least(cmd.actor_roles, AnalyticsRole.ENGINEER)
        params = self._query_validator.sanitize_parameters(
            cmd.parameters, tenant_id=str(cmd.tenant_id)
        )
        started = datetime.now(UTC)
        # Safe in-memory execution: never string-format SQL; return projection rows
        rows = self._safe_execute(query.query_template, params, cmd.tenant_id)
        if len(rows) > MAX_ROWS_ABSOLUTE:
            rows = rows[:MAX_ROWS_ABSOLUTE]
        duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        execution_id = str(QueryExecutionId.generate())
        self._query_results[execution_id] = {
            "execution_id": execution_id,
            "query_id": str(query.query_id),
            "rows": rows,
            "row_count": len(rows),
            "executed_at": started.isoformat(),
        }
        self._audit.append(
            {
                "execution_id": execution_id,
                "query_id": str(query.query_id),
                "tenant_id": str(cmd.tenant_id),
                "executed_by": cmd.executed_by,
                "row_count": len(rows),
                "duration_ms": duration_ms,
                "parameters": {k: str(v) for k, v in params.items()},
            }
        )
        return {
            "execution_id": execution_id,
            "row_count": len(rows),
            "duration_ms": duration_ms,
            "rows": rows[:100],
        }

    def _safe_execute(
        self, template: str, params: dict[str, object], tenant_id: UUID
    ) -> list[dict[str, Any]]:
        """Parameterized-safe projection query (no SQL string formatting)."""
        del template  # validated template; execution uses typed store
        tid = str(params.get("tenant_id") or tenant_id)
        if tid != str(tenant_id):
            # force tenant from context
            tid = str(tenant_id)
        domain = str(params.get("domain") or "vulnerability")
        domain_key = domain.lower().replace(" ", "_")
        if domain_key not in {
            "vulnerability",
            "detection",
            "execution",
            "campaign",
            "exposure",
            "ai_posture",
        }:
            domain_key = "vulnerability"
        return [
            {
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "event_ts": r["event_ts"].isoformat()
                if hasattr(r["event_ts"], "isoformat")
                else str(r["event_ts"]),
            }
            for r in self._store.list_events(UUID(tid), domain_key)
        ]

    async def list_queries(
        self, tenant_id: UUID, actor_roles: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        rows = await self._queries.find_all(TenantId(tenant_id))
        return [
            {
                "query_id": str(q.query_id),
                "name": q.name,
                "domain": q.domain.value,
            }
            for q in rows
        ]

    async def get_query_result(
        self, tenant_id: UUID, execution_id: str, actor_roles: tuple[str, ...]
    ) -> dict[str, Any]:
        require_at_least(actor_roles, AnalyticsRole.VIEWER)
        del tenant_id
        row = self._query_results.get(execution_id)
        if row is None:
            raise ApplicationNotFoundError(execution_id)
        return row

    async def export_dataset(
        self,
        tenant_id: UUID,
        dataset_id: UUID,
        actor_roles: tuple[str, ...],
        *,
        page: int = 1,
        page_size: int = 100,
    ) -> dict[str, Any]:
        require_at_least(actor_roles, AnalyticsRole.ANALYST)
        ds = await self._datasets.find_by_id(TenantId(tenant_id), AnalyticsDataSetId(dataset_id))
        if ds is None:
            raise ApplicationNotFoundError(str(dataset_id))
        domain_key = {
            SecurityDomain.VULNERABILITY: "vulnerability",
            SecurityDomain.DETECTION: "detection",
            SecurityDomain.RED_TEAM: "execution",
            SecurityDomain.CAMPAIGN: "campaign",
            SecurityDomain.EXPOSURE: "exposure",
            SecurityDomain.AI_POSTURE: "ai_posture",
        }.get(ds.domain, "vulnerability")
        rows = self._store.list_events(tenant_id, domain_key)
        page = max(1, page)
        page_size = max(1, min(page_size, 1000))
        start = (page - 1) * page_size
        slice_rows = rows[start : start + page_size]
        return {
            "dataset_id": str(dataset_id),
            "page": page,
            "page_size": page_size,
            "total": len(rows),
            "rows": [
                {
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                }
                for r in slice_rows
            ],
        }

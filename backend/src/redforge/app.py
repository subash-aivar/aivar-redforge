"""Application factory for AIVAR RedForge.

Composes the FastAPI application by registering middleware, routers, and
lifecycle events. This is the single composition root — all wiring happens here.

Usage:
    from redforge.app import create_app
    app = create_app()
"""

import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redforge.api.router import build_root_router
from redforge.application.platform.dynamic_health import (
    make_continuous_validation_scheduler_health_probe,
    make_database_health_probe,
    make_dlq_depth_health_probe,
    make_network_monitoring_scheduler_health_probe,
    make_replay_worker_health_probe,
)
from redforge.application.platform.idempotent_projection_engine import (
    IdempotentProjectionEngine,
)
from redforge.application.platform.replay_worker import DLQReplayWorker
from redforge.application.platform.runtime_container import build_runtime_container
from redforge.application.platform.runtime_contracts import DeadLetterEntry
from redforge.application.platform.startup_validator import validate_startup
from redforge.application.platform.tenant_periodic_runner import TenantPeriodicRunner
from redforge.core.config import Settings, get_settings
from redforge.core.logging import configure_logging, get_logger
from redforge.infrastructure.database.engine import create_engine, dispose_engine
from redforge.infrastructure.middleware.correlation import CorrelationMiddleware
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware
from redforge.infrastructure.middleware.metrics import PrometheusMiddleware
from redforge.infrastructure.middleware.rate_limit import RateLimitMiddleware
from redforge.infrastructure.middleware.request_logging import RequestLoggingMiddleware
from redforge.infrastructure.middleware.security_headers import SecurityHeadersMiddleware
from redforge.infrastructure.rate_limiting import InMemorySlidingWindowLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        settings: Optional settings override. Useful for testing.
                  If None, settings are loaded from environment.

    Returns:
        Fully configured FastAPI application instance.
    """
    settings = settings or get_settings()

    configure_logging(
        log_level=settings.log_level,
        log_format=settings.log_format,
    )

    logger = get_logger(__name__)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # Build runtime container (pure Python, no I/O)
        runtime = build_runtime_container(settings)
        app.state.runtime = runtime

        coordinator = runtime.coordinator

        # session_factory is set in _start_database and used in _start_replay_worker
        _session_factory: Any = None  # async_sessionmaker[AsyncSession] after _start_database

        # Register ordered startup hooks
        async def _start_database() -> None:
            # Lazy imports: keep SQLAlchemy ORM models off the import graph until
            # startup so that SQLite-based unit tests can import create_app without
            # pulling in JSONB column definitions that SQLite cannot compile.
            from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

            from redforge.infrastructure.platform.dead_letter_queue import (
                PostgreSQLDeadLetterQueue,
            )

            nonlocal _session_factory
            # Defense in depth: guarantees every DB-bound dependency
            # provider picks up THIS engine even if a previous app
            # instance's shutdown hook didn't run to completion in this
            # same process (e.g. an aborted lifespan) — see
            # clear_cached_dependencies()'s own docstring for why this
            # matters whenever more than one create_app() lifespan runs
            # in one interpreter.
            from redforge.api.dependencies import clear_cached_dependencies

            clear_cached_dependencies()
            engine = create_engine(
                database_url=settings.database_url,
                echo=settings.debug,
                pool_size=settings.database_pool_size,
            )
            # Startup validation: fails fast if DB unreachable (skipped in test env)
            await validate_startup(settings, engine)

            # Wire durable PostgreSQL DLQ (replaces in-memory placeholder)
            _session_factory = async_sessionmaker(
                bind=engine, class_=AsyncSession, expire_on_commit=False
            )
            runtime.dlq = PostgreSQLDeadLetterQueue(_session_factory)
            # Expose to diagnostic endpoints (GET /runtime/checkpoints needs it)
            runtime.session_factory = _session_factory

            # Wire KnowledgeGraph and register KGProjection (DEBT-S31-2 resolved)
            if runtime.knowledge_graph is not None:
                from redforge.application.platform.projection_engine import (
                    InMemoryReadModelRepository,
                )
                from redforge.application.platform.projections.kg_projection import (
                    KGProjection,
                )

                kg_repo = InMemoryReadModelRepository()
                kg_proj = KGProjection(runtime.knowledge_graph, kg_repo)
                import contextlib

                with contextlib.suppress(Exception):
                    runtime.projection_registry.register(kg_proj)
                    logger.info("kg_projection_registered")

            # Dynamic health probe: live SELECT 1 instead of a static constant
            runtime.health_engine.register(
                "database",
                make_database_health_probe(engine),
            )
            logger.info("database_engine_started", dlq="postgresql")

        async def _start_credential_vault() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("credential_vault_no_session_factory")
                return
            from credential_vault.infrastructure.container import CredentialVaultContainer
            from credential_vault.infrastructure.startup_validator import (
                validate_credential_vault,
            )
            from redforge.api.dependencies import get_effective_access_service

            cv_container = CredentialVaultContainer(
                session_factory=sf,
                effective_access_svc=get_effective_access_service(),
            )
            app.state.cv_container = cv_container
            if settings.environment != "test":
                try:
                    await validate_credential_vault(cv_container)
                except Exception as exc:
                    if settings.environment == "production":
                        raise
                    logger.warning("credential_vault_startup_validation_failed", error=str(exc))
            logger.info("credential_vault_container_started")

        async def _start_vulnerability() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("vulnerability_no_session_factory")
                return
            from vulnerability.infrastructure.container import VulnerabilityContainer

            vuln_container = VulnerabilityContainer(session_factory=sf)
            app.state.vuln_container = vuln_container
            logger.info("vulnerability_container_started")

        async def _start_detection() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("detection_no_session_factory")
                return
            from detection.infrastructure.container import DetectionContainer

            detection_container = DetectionContainer(session_factory=sf)
            app.state.detection_container = detection_container
            logger.info("detection_container_started")

        async def _start_engagement() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("engagement_no_session_factory")
                return
            from engagement.infrastructure.container import EngagementContainer

            engagement_container = EngagementContainer(session_factory=sf)
            app.state.engagement_container = engagement_container
            logger.info("engagement_container_started")

        async def _start_operation() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("operation_no_session_factory")
                return
            from operation.infrastructure.container import OperationContainer

            operation_container = OperationContainer(session_factory=sf)
            app.state.operation_container = operation_container
            logger.info("operation_container_started")

        async def _start_risk_engine() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("risk_engine_no_session_factory")
                return
            from risk_engine.infrastructure.container import RiskEngineContainer

            risk_engine_container = RiskEngineContainer(session_factory=sf)
            app.state.risk_engine_container = risk_engine_container
            logger.info("risk_engine_container_started")

        async def _start_threat_actor_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("threat_actor_intel_no_session_factory")
                return
            from threat_actor_intel.infrastructure.container import ThreatActorIntelContainer

            threat_actor_intel_container = ThreatActorIntelContainer(session_factory=sf)
            app.state.threat_actor_intel_container = threat_actor_intel_container
            logger.info("threat_actor_intel_container_started")

        async def _start_ioc_intelligence() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("ioc_intelligence_no_session_factory")
                return
            from ioc_intelligence.infrastructure.container import IocIntelContainer

            ioc_intel_container = IocIntelContainer(session_factory=sf)
            app.state.ioc_intel_container = ioc_intel_container
            logger.info("ioc_intel_container_started")

        async def _start_attack_pattern_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("attack_pattern_intel_no_session_factory")
                return
            from attack_pattern_intel.infrastructure.container import AttackPatternIntelContainer

            attack_pattern_intel_container = AttackPatternIntelContainer(session_factory=sf)
            app.state.attack_pattern_intel_container = attack_pattern_intel_container
            logger.info("attack_pattern_intel_container_started")

        async def _start_intelligence_relationships() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("intelligence_relationships_no_session_factory")
                return
            from intelligence_relationships.infrastructure.container import (
                IntelligenceRelationshipsContainer,
            )

            intelligence_relationships_container = IntelligenceRelationshipsContainer(
                session_factory=sf
            )
            app.state.intelligence_relationships_container = (
                intelligence_relationships_container
            )
            logger.info("intelligence_relationships_container_started")

        async def _start_malware_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("malware_intel_no_session_factory")
                return
            from malware_intel.infrastructure.container import MalwareIntelContainer

            malware_intel_container = MalwareIntelContainer(session_factory=sf)
            app.state.malware_intel_container = malware_intel_container
            logger.info("malware_intel_container_started")

        async def _start_campaign_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("campaign_intel_no_session_factory")
                return
            from campaign_intel.infrastructure.container import CampaignIntelContainer

            campaign_intel_container = CampaignIntelContainer(session_factory=sf)
            app.state.campaign_intel_container = campaign_intel_container
            logger.info("campaign_intel_container_started")

        async def _start_tool_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("tool_intel_no_session_factory")
                return
            from tool_intel.infrastructure.container import ToolIntelContainer

            tool_intel_container = ToolIntelContainer(session_factory=sf)
            app.state.tool_intel_container = tool_intel_container
            logger.info("tool_intel_container_started")

        async def _start_infrastructure_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("infrastructure_intel_no_session_factory")
                return
            from infrastructure_intel.infrastructure.container import (
                InfrastructureIntelContainer,
            )

            infrastructure_intel_container = InfrastructureIntelContainer(session_factory=sf)
            app.state.infrastructure_intel_container = infrastructure_intel_container
            logger.info("infrastructure_intel_container_started")

        async def _start_threat_report_intel() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("threat_report_intel_no_session_factory")
                return
            from threat_report_intel.infrastructure.container import (
                ThreatReportIntelContainer,
            )

            threat_report_intel_container = ThreatReportIntelContainer(session_factory=sf)
            app.state.threat_report_intel_container = threat_report_intel_container
            logger.info("threat_report_intel_container_started")

        async def _start_attack_surface_management() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("attack_surface_management_no_session_factory")
                return
            from attack_surface_management.infrastructure.container import (
                AttackSurfaceManagementContainer,
            )

            attack_surface_management_container = AttackSurfaceManagementContainer(
                session_factory=sf
            )
            app.state.attack_surface_management_container = attack_surface_management_container
            logger.info("attack_surface_management_container_started")

        async def _start_scanning() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("scanning_no_session_factory")
                return
            from vulnerability.infrastructure.scanning.container import ScanningContainer

            scanning_container = ScanningContainer(session_factory=sf)
            app.state.scanning_container = scanning_container
            logger.info("scanning_container_started")

        async def _start_execution() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("execution_no_session_factory")
                return
            from execution.infrastructure.container import ExecutionContainer

            execution_container = ExecutionContainer(session_factory=sf)
            app.state.execution_container = execution_container
            logger.info("execution_container_started")

        async def _start_operator() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("operator_no_session_factory")
                return
            from red_team_operator.infrastructure.container import OperatorContainer

            operator_container = OperatorContainer(session_factory=sf)
            app.state.operator_container = operator_container
            logger.info("operator_container_started")

        async def _start_evidence() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("evidence_no_session_factory")
                return
            from evidence.infrastructure.container import EvidenceContainer

            evidence_container = EvidenceContainer(session_factory=sf)
            app.state.evidence_container = evidence_container
            logger.info("evidence_container_started")

        async def _start_payload() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("payload_no_session_factory")
                return
            from payload.infrastructure.container import PayloadContainer

            payload_container = PayloadContainer(session_factory=sf)
            app.state.payload_container = payload_container
            logger.info("payload_container_started")

        async def _start_credential_vault_workers() -> None:
            if settings.environment == "test":
                return
            sf = _session_factory
            cv_container = getattr(app.state, "cv_container", None)
            if sf is None or cv_container is None:
                logger.warning("credential_vault_workers_skipped")
                return

            import os
            import uuid

            from credential_vault.domain.services.policy_evaluator import PolicyEvaluatorService
            from credential_vault.domain.services.rotation_planner import RotationPlannerService
            from credential_vault.workers.dek_rewrap.dek_rewrap_progress_repository import (
                DekRewrapProgressRepository,
            )
            from credential_vault.workers.dek_rewrap.dek_rewrap_worker import DekRewrapWorker
            from credential_vault.workers.expiration_scanner.expiration_scanner_worker import (
                ExpirationScannerWorker,
            )
            from credential_vault.workers.expiration_scanner.expiration_schedule_repository import (
                ExpirationScheduleRepository,
            )
            from credential_vault.workers.rotation_scheduler.rotation_schedule_repository import (
                RotationScheduleRepository,
            )
            from credential_vault.workers.rotation_scheduler.rotation_scheduler_worker import (
                RotationSchedulerWorker,
            )
            from credential_vault.workers.version_pruner.version_pruner_worker import (
                VersionPrunerWorker,
            )
            from credential_vault.workers.worker_host import CredentialVaultWorkerHost

            rotation_repo = RotationScheduleRepository(sf)
            expiration_repo = ExpirationScheduleRepository(sf)
            rewrap_target = os.environ.get("CREDENTIAL_VAULT_REWRAP_MASTER_KEY_ID")
            rewrap_worker = None
            if rewrap_target:
                rewrap_worker = DekRewrapWorker(
                    kms_adapter=cv_container.kms_adapter,
                    rewrap_repo=DekRewrapProgressRepository(sf),
                    session_factory=sf,
                    target_master_key_id=rewrap_target,
                )

            worker_host = CredentialVaultWorkerHost(
                rotation_worker=RotationSchedulerWorker(
                    credential_service=cv_container._inner_credential_service,
                    schedule_repo=rotation_repo,
                    rotation_planner=RotationPlannerService(),
                    credential_repo_factory=sf,
                    worker_id=f"rotation-scheduler-{uuid.uuid4().hex[:8]}",
                ),
                expiration_worker=ExpirationScannerWorker(
                    credential_service=cv_container._inner_credential_service,
                    schedule_repo=expiration_repo,
                    policy_evaluator=PolicyEvaluatorService(),
                    session_factory=sf,
                    event_publisher=cv_container.event_publisher,
                    worker_id=f"expiration-scanner-{uuid.uuid4().hex[:8]}",
                ),
                pruner_worker=VersionPrunerWorker(session_factory=sf),
                rewrap_worker=rewrap_worker,
            )
            await worker_host.start()
            runtime.credential_vault_worker_host = worker_host  # type: ignore[attr-defined]
            app.state.credential_vault_worker_host = worker_host
            logger.info("credential_vault_workers_started")

        async def _shutdown_credential_vault_workers() -> None:
            worker_host = getattr(app.state, "credential_vault_worker_host", None)
            if worker_host is not None:
                await worker_host.stop()
                logger.info("credential_vault_workers_stopped")

        async def _start_replay_worker() -> None:
            # Fail fast if no projections are registered — replay would be a no-op.
            runtime.projection_registry.validate()
            sf = _session_factory

            async def _real_replay_fn(entry: DeadLetterEntry) -> bool:
                if sf is None:
                    logger.error("replay_fn_no_session_factory", event_id=entry.event_id)
                    return False
                # Lazy imports: same reason as _start_database — avoid pulling in
                # JSONB ORM models at module import time.
                from redforge.infrastructure.platform.checkpoint_repository import (
                    PostgreSQLCheckpointRepository,
                    PostgreSQLReadModelRepository,
                )
                from redforge.infrastructure.platform.event_store import PostgreSQLEventStore

                t0 = time.monotonic()
                try:
                    async with sf() as session, session.begin():
                        event_store = PostgreSQLEventStore(session)
                        envelope = await event_store.fetch_by_event_id(entry.event_id)
                        if envelope is None:
                            logger.warning(
                                "replay_event_not_found",
                                event_id=entry.event_id,
                                entry_id=entry.entry_id,
                                source_projection=entry.source_projection,
                            )
                            return False

                        # ── P0 Security: cross-tenant integrity check ──────────
                        # entry.organization_id is set at store() time from the
                        # JWT-authenticated context. The event_id fetch has no
                        # org filter (by design). We verify they match to prevent
                        # cross-tenant replay from a poisoned or misrouted DLQ entry.
                        if entry.organization_id != envelope.organization_id:
                            logger.error(
                                "replay_cross_tenant_rejected",
                                entry_id=entry.entry_id,
                                event_id=entry.event_id,
                                entry_org=entry.organization_id,
                                envelope_org=envelope.organization_id,
                            )
                            runtime.metrics.record_counter(
                                "dlq.replay.cross_tenant_rejected",
                                1,
                                labels={"projection": entry.source_projection},
                            )
                            return False

                        checkpoint_repo = PostgreSQLCheckpointRepository(session)
                        engine_proj = IdempotentProjectionEngine(checkpoint_repo)
                        # Register projections BEFORE load_checkpoints so checkpoint
                        # positions are seeded for each registered projection name.
                        runtime.projection_registry.register_all_with(engine_proj)

                        t_cp = time.monotonic()
                        await engine_proj.load_checkpoints()
                        checkpoint_latency_ms = int((time.monotonic() - t_cp) * 1000)

                        events_before = engine_proj.events_processed
                        skipped_before = engine_proj.events_skipped
                        t_handler = time.monotonic()
                        await engine_proj.process(envelope)
                        handler_duration_ms = int((time.monotonic() - t_handler) * 1000)

                        events_replayed = engine_proj.events_processed - events_before
                        events_skipped = engine_proj.events_skipped - skipped_before
                        handlers_invoked = len(engine_proj.registered_projections())

                        # ── Durable read model flush ───────────────────────────
                        # After handlers update in-memory state, flush to PostgreSQL
                        # within the same transaction so reads survive process restart.
                        pg_repo = PostgreSQLReadModelRepository(session)
                        await runtime.projection_registry.flush_all_to_durable_repo(
                            pg_repo, envelope.organization_id
                        )

                    # ── Record handler-level metrics ───────────────────────────
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    runtime.metrics.record_counter(
                        "dlq.replay.handlers_invoked",
                        float(handlers_invoked),
                        labels={"projection": entry.source_projection},
                    )
                    runtime.metrics.record_histogram(
                        "dlq.replay.projection_execution_time",
                        float(handler_duration_ms),
                        labels={"projection": entry.source_projection},
                    )
                    runtime.metrics.record_histogram(
                        "dlq.replay.checkpoint_latency",
                        float(checkpoint_latency_ms),
                        labels={"projection": entry.source_projection},
                    )
                    runtime.metrics.record_counter(
                        "dlq.replay.events_replayed",
                        float(events_replayed),
                        labels={"projection": entry.source_projection},
                    )
                    runtime.metrics.record_counter(
                        "dlq.replay.events_skipped",
                        float(events_skipped),
                        labels={"projection": entry.source_projection},
                    )
                    logger.info(
                        "replay_success",
                        event_id=entry.event_id,
                        source_projection=entry.source_projection,
                        organization_id=entry.organization_id,
                        duration_ms=duration_ms,
                        handlers_invoked=handlers_invoked,
                        events_replayed=events_replayed,
                        events_skipped=events_skipped,
                        checkpoint_latency_ms=checkpoint_latency_ms,
                    )
                    runtime.metrics.record_counter(
                        "dlq.replay.success",
                        1,
                        labels={"projection": entry.source_projection},
                    )
                    return True
                except Exception as exc:
                    duration_ms = int((time.monotonic() - t0) * 1000)
                    logger.error(
                        "replay_failure",
                        event_id=entry.event_id,
                        source_projection=entry.source_projection,
                        organization_id=entry.organization_id,
                        error=type(exc).__name__,
                        duration_ms=duration_ms,
                    )
                    runtime.metrics.record_counter(
                        "dlq.replay.projection_failures",
                        1,
                        labels={"projection": entry.source_projection},
                    )
                    runtime.metrics.record_counter(
                        "dlq.replay.failure",
                        1,
                        labels={"projection": entry.source_projection},
                    )
                    return False

            worker = DLQReplayWorker(
                dlq=runtime.dlq,
                replay_fn=_real_replay_fn,
                poll_interval_s=settings.runtime_replay_poll_interval_s,
                max_concurrent=settings.runtime_replay_max_concurrent,
                batch_size=settings.runtime_replay_batch_size,
                replay_max_retries=settings.runtime_replay_max_retries,
            )
            await worker.start()
            runtime.replay_worker = worker

            runtime.health_engine.register(
                "replay_worker",
                make_replay_worker_health_probe(worker),
            )
            runtime.health_engine.register(
                "dlq",
                make_dlq_depth_health_probe(runtime.dlq),
            )
            logger.info("replay_worker_started")

        async def _start_continuous_validation_scheduler() -> None:
            import uuid

            from redforge.application.ai_targets import AITargetService
            from redforge.application.authorization import ExecutionPolicyService
            from redforge.application.continuous_validation.drift_service import (
                SecurityDriftService,
            )
            from redforge.application.continuous_validation.processor import (
                ContinuousValidationProcessor,
            )
            from redforge.application.continuous_validation.scheduler_worker import (
                ContinuousValidationSchedulerWorker,
            )
            from redforge.application.inventory.tenant_asset_service import TenantAssetService
            from redforge.application.security_conditions.service import (
                TenantSecurityConditionService,
            )
            from redforge.application.security_correlation.rules import (
                CorrelationRuleRegistry,
                MultipleSecurityConditionsOnAssetRule,
                PublicSensitiveServiceContextRule,
            )
            from redforge.application.security_correlation.service import (
                TenantSecurityCorrelationService,
            )
            from redforge.application.validation_execution.adaptive_rules import (
                default_adaptive_rule_registry,
            )
            from redforge.application.validation_execution.execution_service import (
                ValidationExecutionService,
            )
            from redforge.application.validation_execution.protocol_validators import (
                default_protocol_validator_registry,
            )
            from redforge.infrastructure.events import NullEventPublisher

            sf = _session_factory
            if sf is None:
                logger.error("continuous_validation_scheduler_no_session_factory")
                return

            ai_target_service = AITargetService(sf, NullEventPublisher())
            asset_service = TenantAssetService(sf)
            condition_service = TenantSecurityConditionService(sf)
            correlation_registry = CorrelationRuleRegistry()
            correlation_registry.register(
                PublicSensitiveServiceContextRule(asset_service, condition_service),
            )
            correlation_registry.register(
                MultipleSecurityConditionsOnAssetRule(condition_service),
            )
            correlation_service = TenantSecurityCorrelationService(sf, correlation_registry)
            execution_policy_service = ExecutionPolicyService(sf)
            execution_service = ValidationExecutionService(
                sf,
                # ExecutionPolicyService.evaluate() returns
                # ExecutionPolicyResultDTO, which structurally satisfies
                # both application.campaigns.contracts and
                # application.validation_execution.contracts'
                # independently-declared ExecutionPolicyDecisionResult
                # Protocols (same three str fields, by design — see
                # validation_execution/contracts.py's own docstring) —
                # mypy doesn't resolve that structural equivalence across
                # a Coroutine return position, hence the ignore.
                execution_policy_service,  # type: ignore[arg-type]
                ai_target_service,
                asset_service,
                condition_service,
                default_adaptive_rule_registry(),
                correlation_service,
                default_protocol_validator_registry(),
            )
            drift_service = SecurityDriftService(sf)
            processor = ContinuousValidationProcessor(
                sf,
                execution_service,
                ai_target_service,
                asset_service,
                condition_service,
                correlation_service,
                drift_service,
            )

            worker = ContinuousValidationSchedulerWorker(
                processor=processor,
                worker_id=f"scheduler-{uuid.uuid4().hex[:12]}",
                poll_interval_s=settings.runtime_continuous_validation_poll_interval_s,
                max_concurrent=settings.runtime_continuous_validation_max_concurrent,
                batch_size=settings.runtime_continuous_validation_batch_size,
            )
            await worker.start()
            runtime.continuous_validation_scheduler = worker

            runtime.health_engine.register(
                "continuous_validation_scheduler",
                make_continuous_validation_scheduler_health_probe(worker),
            )
            logger.info("continuous_validation_scheduler_started")

        async def _start_runtime_health_transition_worker() -> None:
            from redforge.application.security_operations.runtime_health_projector import (
                RuntimeHealthTransitionProjector,
            )
            from redforge.application.security_operations.runtime_health_worker import (
                RuntimeHealthTransitionWorker,
            )

            sf = _session_factory
            if sf is None:
                logger.error("runtime_health_transition_worker_no_session_factory")
                return

            projector = RuntimeHealthTransitionProjector(runtime.health_engine, sf)
            worker = RuntimeHealthTransitionWorker(
                projector=projector,
                poll_interval_s=settings.runtime_health_transition_poll_interval_s,
            )
            await worker.start()
            runtime.runtime_health_transition_worker = worker
            logger.info("runtime_health_transition_worker_started")

        async def _start_network_monitoring_scheduler() -> None:
            import uuid

            from redforge.application.inventory.tenant_asset_service import TenantAssetService
            from redforge.application.network_security.orchestrator import (
                NetworkValidationOrchestrator,
            )
            from redforge.application.network_security.scheduler import (
                NetworkMonitoringProcessor,
            )
            from redforge.application.network_security.scheduler_worker import (
                NetworkMonitoringSchedulerWorker,
            )
            from redforge.application.security_conditions.service import (
                TenantSecurityConditionService,
            )
            from redforge.application.security_correlation.rules import (
                CorrelationRuleRegistry,
                MultipleSecurityConditionsOnAssetRule,
                PublicSensitiveServiceContextRule,
            )
            from redforge.application.security_correlation.service import (
                TenantSecurityCorrelationService,
            )

            sf = _session_factory
            if sf is None:
                logger.error("network_monitoring_scheduler_no_session_factory")
                return

            asset_service = TenantAssetService(sf)
            condition_service = TenantSecurityConditionService(sf)
            correlation_registry = CorrelationRuleRegistry()
            correlation_registry.register(
                PublicSensitiveServiceContextRule(asset_service, condition_service),
            )
            correlation_registry.register(
                MultipleSecurityConditionsOnAssetRule(condition_service),
            )
            correlation_service = TenantSecurityCorrelationService(sf, correlation_registry)
            orchestrator = NetworkValidationOrchestrator(
                sf,
                asset_service,
                condition_service,
                correlation_service,
            )
            processor = NetworkMonitoringProcessor(sf, orchestrator)

            worker = NetworkMonitoringSchedulerWorker(
                processor=processor,
                worker_id=f"network-scheduler-{uuid.uuid4().hex[:12]}",
                poll_interval_s=settings.runtime_network_monitoring_poll_interval_s,
                max_concurrent=settings.runtime_network_monitoring_max_concurrent,
                batch_size=settings.runtime_network_monitoring_batch_size,
            )
            await worker.start()
            runtime.network_monitoring_scheduler = worker

            runtime.health_engine.register(
                "network_monitoring_scheduler",
                make_network_monitoring_scheduler_health_probe(worker),
            )
            logger.info("network_monitoring_scheduler_started")

        coordinator.register_startup("database", _start_database)
        coordinator.register_startup("credential_vault", _start_credential_vault)
        coordinator.register_startup("vulnerability", _start_vulnerability)
        coordinator.register_startup("detection", _start_detection)
        coordinator.register_startup("engagement", _start_engagement)
        coordinator.register_startup("operation", _start_operation)
        coordinator.register_startup("risk_engine", _start_risk_engine)
        coordinator.register_startup("threat_actor_intel", _start_threat_actor_intel)
        coordinator.register_startup("ioc_intelligence", _start_ioc_intelligence)
        coordinator.register_startup("attack_pattern_intel", _start_attack_pattern_intel)
        coordinator.register_startup(
            "intelligence_relationships", _start_intelligence_relationships
        )
        coordinator.register_startup("malware_intel", _start_malware_intel)
        coordinator.register_startup("campaign_intel", _start_campaign_intel)
        coordinator.register_startup("tool_intel", _start_tool_intel)
        coordinator.register_startup(
            "infrastructure_intel", _start_infrastructure_intel
        )
        coordinator.register_startup("threat_report_intel", _start_threat_report_intel)
        coordinator.register_startup("attack_surface_management", _start_attack_surface_management)
        coordinator.register_startup("scanning", _start_scanning)
        coordinator.register_startup("execution", _start_execution)
        coordinator.register_startup("operator", _start_operator)
        coordinator.register_startup("evidence", _start_evidence)
        coordinator.register_startup("payload", _start_payload)
        coordinator.register_startup("replay_worker", _start_replay_worker)
        coordinator.register_startup(
            "continuous_validation_scheduler",
            _start_continuous_validation_scheduler,
        )
        coordinator.register_startup(
            "credential_vault_workers",
            _start_credential_vault_workers,
        )
        coordinator.register_startup(
            "runtime_health_transition_worker",
            _start_runtime_health_transition_worker,
        )
        coordinator.register_startup(
            "network_monitoring_scheduler",
            _start_network_monitoring_scheduler,
        )

        async def _start_ddos_detection_worker() -> None:
            if _session_factory is None:
                logger.warning("ddos_detection_worker_no_session_factory")
                return
            from redforge.application.ddos.detection_worker import DDoSDetectionWorker

            worker = DDoSDetectionWorker(
                session_factory=_session_factory,
                poll_seconds=getattr(settings, "runtime_ddos_detection_poll_seconds", 60),
            )
            worker.start()
            runtime.ddos_detection_worker = worker  # type: ignore[attr-defined]
            app.state.ddos_detection_worker = worker
            logger.info("ddos_detection_worker_started")

        coordinator.register_startup("ddos_detection_worker", _start_ddos_detection_worker)

        async def _start_behavior_detection_worker() -> None:
            if _session_factory is None:
                logger.warning("behavior_detection_worker_no_session_factory")
                return
            from redforge.application.behavior.detection_worker import BehaviorDetectionWorker

            worker = BehaviorDetectionWorker(
                session_factory=_session_factory,
                poll_seconds=getattr(settings, "runtime_behavior_poll_seconds", 300),
            )
            worker.start()
            runtime.behavior_detection_worker = worker  # type: ignore[attr-defined]
            app.state.behavior_detection_worker = worker
            logger.info("behavior_detection_worker_started")

        coordinator.register_startup("behavior_detection_worker", _start_behavior_detection_worker)

        async def _start_correlation_worker() -> None:
            if _session_factory is None:
                logger.warning("correlation_worker_no_session_factory")
                return
            from redforge.application.investigations.correlation_worker import CorrelationWorker

            worker = CorrelationWorker(session_factory=_session_factory)
            worker.start()
            runtime.correlation_worker = worker  # type: ignore[attr-defined]
            app.state.correlation_worker = worker
            logger.info("correlation_worker_started")

        coordinator.register_startup("correlation_worker", _start_correlation_worker)

        async def _start_feed_sync_scheduler() -> None:
            if _session_factory is None:
                logger.warning("feed_sync_scheduler_no_session_factory")
                return
            from redforge.application.threat_intel.feed_sync_orchestration_service import (
                FeedSyncOrchestrationService,
            )
            from redforge.application.threat_intel.feed_sync_worker import (
                FeedSyncSchedulerWorker,
            )
            from redforge.application.threat_intel.stix_taxii_connector import (
                StixTaxiiFeedConnector,
            )
            from redforge.domain.threat_intel.feed_value_objects import FeedSourceKind

            # M22 Phase 3 (STIX/TAXII Integration): the only connector
            # registered so far. Every other `FeedSourceKind` still has
            # no executor, so triggering a sync for a feed of that kind
            # continues to fail honestly with `UnknownFeedConnectorError`
            # (see `feed_connector.py`'s module docstring).
            runtime.feed_connector_registry.register(
                FeedSourceKind.STIX_TAXII_PULL,
                StixTaxiiFeedConnector(
                    session_factory=_session_factory,
                    credential_resolver=runtime.credential_resolver,
                    metrics=runtime.metrics,
                ),
            )

            orchestration_service = FeedSyncOrchestrationService(
                _session_factory, runtime.feed_connector_registry
            )
            worker = FeedSyncSchedulerWorker(
                session_factory=_session_factory,
                orchestration_service=orchestration_service,
                poll_seconds=getattr(settings, "runtime_feed_sync_poll_seconds", 60),
            )
            worker.start()
            runtime.feed_sync_scheduler = worker
            app.state.feed_sync_scheduler = worker
            logger.info("feed_sync_scheduler_started")

        coordinator.register_startup("feed_sync_scheduler", _start_feed_sync_scheduler)

        async def _start_m22_ti_sync_workers() -> None:
            """M22 Phase 6 — ATT&CK/vuln sync + indicator refresh workers."""
            if _session_factory is None:
                logger.warning("m22_ti_sync_workers_no_session_factory")
                return
            from redforge.application.threat_intel.attack_technique_sync_worker import (
                AttackTechniqueSyncWorker,
            )
            from redforge.application.threat_intel.enrichment_service import (
                IndicatorEnrichmentService,
            )
            from redforge.application.threat_intel.feed_sync_orchestration_service import (
                FeedSyncOrchestrationService,
            )
            from redforge.application.threat_intel.indicator_refresh_worker import (
                IndicatorRefreshWorker,
            )
            from redforge.application.threat_intel.sync_orchestration_service import (
                ThreatIntelSyncOrchestrationService,
            )
            from redforge.application.threat_intel.threat_fusion_service import (
                ThreatFusionService,
            )
            from redforge.application.threat_intel.vulnerability_sync_worker import (
                VulnerabilitySyncWorker,
            )

            feed_orch = FeedSyncOrchestrationService(
                _session_factory, runtime.feed_connector_registry
            )
            sync_service = ThreatIntelSyncOrchestrationService(
                _session_factory,
                feed_orchestration=feed_orch,
                fusion_service=ThreatFusionService(_session_factory),
            )
            tech_worker = AttackTechniqueSyncWorker(sync_service, session_factory=_session_factory)
            vuln_worker = VulnerabilitySyncWorker(sync_service, session_factory=_session_factory)
            refresh_worker = IndicatorRefreshWorker(
                _session_factory, IndicatorEnrichmentService(_session_factory)
            )
            tech_worker.start()
            vuln_worker.start()
            refresh_worker.start()
            runtime.attack_technique_sync_worker = tech_worker  # type: ignore[attr-defined]
            runtime.vulnerability_sync_worker = vuln_worker  # type: ignore[attr-defined]
            runtime.indicator_refresh_worker = refresh_worker  # type: ignore[attr-defined]
            app.state.attack_technique_sync_worker = tech_worker
            app.state.vulnerability_sync_worker = vuln_worker
            app.state.indicator_refresh_worker = refresh_worker
            logger.info("m22_ti_sync_workers_started")

        coordinator.register_startup("m22_ti_sync_workers", _start_m22_ti_sync_workers)

        # ── Tenant-scheduler-backed bounded contexts ────────────────────────
        # These contexts define a Scheduler.tick()/tick_all() entry point but,
        # unlike the claim-based pollers above, have no internal poll loop —
        # TenantPeriodicRunner supplies it. See its module docstring.
        def _make_tenant_query_service() -> Any:
            from redforge.application.platform_identity.query_service import (
                PlatformQueryService,
            )

            sf = _session_factory
            if sf is None:
                return None
            return PlatformQueryService(sf)

        async def _start_analytics_scheduler() -> None:
            from analytics.api.dependencies import get_container

            container = get_container()
            app.state.analytics_container = container
            tqs = _make_tenant_query_service()
            if tqs is None:
                logger.warning("analytics_scheduler_no_session_factory")
                return
            runner = TenantPeriodicRunner(
                "analytics_scheduler",
                container.scheduler.daily_tick,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_analytics_scheduler_poll_s", 3600.0),
            )
            await runner.start()
            runtime.analytics_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("analytics_scheduler_started")

        coordinator.register_startup("analytics_scheduler", _start_analytics_scheduler)

        async def _start_automated_action_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("automated_action_scheduler_no_session_factory")
                return
            from automated_action.infrastructure.container import AutomatedActionContainer

            container = AutomatedActionContainer(session_factory=sf)
            app.state.automated_action_container = container
            tqs = _make_tenant_query_service()
            runner = TenantPeriodicRunner(
                "automated_action_scheduler",
                container.scheduler.tick_all,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_automated_action_poll_s", 30.0),
            )
            await runner.start()
            runtime.automated_action_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("automated_action_scheduler_started")

        coordinator.register_startup(
            "automated_action_scheduler", _start_automated_action_scheduler
        )

        async def _start_autonomous_intelligence_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("autonomous_intelligence_scheduler_no_session_factory")
                return
            from autonomous_intelligence.infrastructure.container import (
                AutonomousIntelligenceContainer,
            )

            container = AutonomousIntelligenceContainer(session_factory=sf)
            app.state.autonomous_intelligence_container = container
            tqs = _make_tenant_query_service()
            runner = TenantPeriodicRunner(
                "autonomous_intelligence_scheduler",
                container.scheduler.tick_all,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_autonomous_intelligence_poll_s", 300.0),
            )
            await runner.start()
            runtime.autonomous_intelligence_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("autonomous_intelligence_scheduler_started")

        coordinator.register_startup(
            "autonomous_intelligence_scheduler", _start_autonomous_intelligence_scheduler
        )

        async def _start_exposure_reporting_scheduler() -> None:
            from exposure_reporting.api.dependencies import get_container

            container = get_container()
            app.state.exposure_reporting_container = container
            tqs = _make_tenant_query_service()
            if tqs is None:
                logger.warning("exposure_reporting_scheduler_no_session_factory")
                return

            async def _tick(tenant_id: Any) -> None:
                await container.worker.rebuild_projections(tenant_id, ("exposure:admin",))

            runner = TenantPeriodicRunner(
                "exposure_reporting_scheduler",
                _tick,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_exposure_reporting_poll_s", 900.0),
            )
            await runner.start()
            runtime.exposure_reporting_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("exposure_reporting_scheduler_started")

        coordinator.register_startup(
            "exposure_reporting_scheduler", _start_exposure_reporting_scheduler
        )

        async def _start_incident_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("incident_scheduler_no_session_factory")
                return
            from incident.infrastructure.container import IncidentContainer

            container = IncidentContainer(session_factory=sf)
            app.state.incident_container = container
            runner = TenantPeriodicRunner(
                "incident_scheduler",
                container.scheduler.tick_all,
                per_tenant=False,
                poll_interval_s=getattr(settings, "runtime_incident_scheduler_poll_s", 60.0),
            )
            await runner.start()
            runtime.incident_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("incident_scheduler_started")

        coordinator.register_startup("incident_scheduler", _start_incident_scheduler)

        async def _start_playbook_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("playbook_scheduler_no_session_factory")
                return
            from playbook.infrastructure.container import PlaybookContainer

            container = PlaybookContainer(session_factory=sf)
            app.state.playbook_container = container

            async def _tick() -> None:
                container.scheduler.tick_all()

            runner = TenantPeriodicRunner(
                "playbook_scheduler",
                _tick,
                per_tenant=False,
                poll_interval_s=getattr(settings, "runtime_playbook_scheduler_poll_s", 30.0),
            )
            await runner.start()
            runtime.playbook_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("playbook_scheduler_started")

        coordinator.register_startup("playbook_scheduler", _start_playbook_scheduler)

        async def _start_posture_forecasting_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("posture_forecasting_scheduler_no_session_factory")
                return
            from posture_forecasting.infrastructure.container import (
                PostureForecastingContainer,
            )

            container = PostureForecastingContainer(session_factory=sf)
            app.state.posture_forecasting_container = container
            tqs = _make_tenant_query_service()
            runner = TenantPeriodicRunner(
                "posture_forecasting_scheduler",
                container.scheduler.tick_all,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_posture_forecasting_poll_s", 3600.0),
            )
            await runner.start()
            runtime.posture_forecasting_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("posture_forecasting_scheduler_started")

        coordinator.register_startup(
            "posture_forecasting_scheduler", _start_posture_forecasting_scheduler
        )

        async def _start_regulatory_notification_scheduler() -> None:
            from regulatory_notification.infrastructure.container import (
                RegulatoryNotificationContainer,
            )

            container = RegulatoryNotificationContainer()
            app.state.regulatory_container = container

            async def _tick() -> None:
                await container.scheduler.tick_all()

            runner = TenantPeriodicRunner(
                "regulatory_notification_scheduler",
                _tick,
                per_tenant=False,
                poll_interval_s=getattr(settings, "runtime_regulatory_notification_poll_s", 300.0),
            )
            await runner.start()
            runtime.regulatory_notification_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("regulatory_notification_scheduler_started")

        coordinator.register_startup(
            "regulatory_notification_scheduler", _start_regulatory_notification_scheduler
        )

        async def _start_reporting_scheduler() -> None:
            from reporting.api.dependencies import get_container

            container = await get_container()
            app.state.reporting_container = container

            async def _tick() -> None:
                await container.scheduler_worker.tick()

            runner = TenantPeriodicRunner(
                "reporting_scheduler",
                _tick,
                per_tenant=False,
                poll_interval_s=getattr(settings, "runtime_reporting_scheduler_poll_s", 60.0),
            )
            await runner.start()
            runtime.reporting_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("reporting_scheduler_started")

        coordinator.register_startup("reporting_scheduler", _start_reporting_scheduler)

        async def _start_ioc_expiry_scheduler() -> None:
            # M51.2 Slice 2.1: promotes the previously external-cron-only
            # `POST /iocs/maintenance/expire-lapsed` sweep to the same
            # in-process periodic-runner pattern already used platform-wide
            # for exactly this shape of job (global, non-per-tenant,
            # idempotent bulk operation) — see regulatory_notification_
            # scheduler/reporting_scheduler above. Horizontally safe: two
            # app instances each running this tick concurrently rely on
            # `IOCApplicationService.expire_lapsed_iocs`'s own per-row
            # optimistic-concurrency handling (row_version), not on a
            # separate claim/lease table, since the underlying operation
            # is idempotent and cheap enough that a lease adds no real
            # safety over what OCC already guarantees. The endpoint
            # remains available too (manual trigger / external cron), and
            # calls the exact same application-service method.
            sf = _session_factory
            if sf is None:
                logger.warning("ioc_expiry_scheduler_no_session_factory")
                return

            async def _tick() -> None:
                from ioc_intelligence.application._auth import IocIntelRole

                container = app.state.ioc_intel_container
                session = container.new_session()
                try:
                    svc = container.build_service(session)
                    expired_count = await svc.expire_lapsed_iocs(
                        actor_roles=(IocIntelRole.PLATFORM_ADMIN.value,)
                    )
                    if expired_count:
                        logger.info(
                            "ioc_expiry_scheduler_tick_completed",
                            expired_count=expired_count,
                        )
                finally:
                    await session.close()

            runner = TenantPeriodicRunner(
                "ioc_expiry_scheduler",
                _tick,
                per_tenant=False,
                poll_interval_s=getattr(settings, "runtime_ioc_expiry_scheduler_poll_s", 300.0),
            )
            await runner.start()
            runtime.ioc_expiry_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("ioc_expiry_scheduler_started")

        coordinator.register_startup("ioc_expiry_scheduler", _start_ioc_expiry_scheduler)

        async def _start_threat_hunt_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("threat_hunt_scheduler_no_session_factory")
                return
            from threat_hunt.infrastructure.container import ThreatHuntContainer

            container = ThreatHuntContainer(session_factory=sf)
            app.state.threat_hunt_container = container
            tqs = _make_tenant_query_service()
            runner = TenantPeriodicRunner(
                "threat_hunt_scheduler",
                container.scheduler.tick,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_threat_hunt_poll_s", 300.0),
            )
            await runner.start()
            runtime.threat_hunt_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("threat_hunt_scheduler_started")

        coordinator.register_startup("threat_hunt_scheduler", _start_threat_hunt_scheduler)

        async def _start_integration_hub_scheduler() -> None:
            sf = _session_factory
            if sf is None:
                logger.warning("integration_hub_scheduler_no_session_factory")
                return
            from integration_hub.infrastructure.container import IntegrationHubContainer

            cv_container = getattr(app.state, "cv_container", None)
            credential_service = (
                cv_container.credential_service if cv_container is not None else None
            )
            container = IntegrationHubContainer(
                session_factory=sf, credential_service=credential_service
            )
            app.state.integration_hub_container = container
            tqs = _make_tenant_query_service()
            runner = TenantPeriodicRunner(
                "integration_hub_scheduler",
                container.scheduler.tick,
                per_tenant=True,
                tenant_query_service=tqs,
                poll_interval_s=getattr(settings, "runtime_integration_hub_poll_s", 300.0),
            )
            await runner.start()
            runtime.integration_hub_scheduler_runner = runner  # type: ignore[attr-defined]
            logger.info("integration_hub_scheduler_started")

        coordinator.register_startup("integration_hub_scheduler", _start_integration_hub_scheduler)

        # Register shutdown hooks (run in reverse registration order)
        async def _shutdown_ddos_detection_worker() -> None:
            worker = getattr(runtime, "ddos_detection_worker", None)
            if worker is not None:
                await worker.stop()
                logger.info("ddos_detection_worker_stopped")

        async def _shutdown_network_monitoring_scheduler() -> None:
            if runtime.network_monitoring_scheduler is not None:
                await runtime.network_monitoring_scheduler.stop()
                logger.info("network_monitoring_scheduler_stopped")

        async def _shutdown_runtime_health_transition_worker() -> None:
            if runtime.runtime_health_transition_worker is not None:
                await runtime.runtime_health_transition_worker.stop()
                logger.info("runtime_health_transition_worker_stopped")

        async def _shutdown_continuous_validation_scheduler() -> None:
            if runtime.continuous_validation_scheduler is not None:
                await runtime.continuous_validation_scheduler.stop()
                logger.info("continuous_validation_scheduler_stopped")

        async def _shutdown_replay_worker() -> None:
            if runtime.replay_worker is not None:
                await runtime.replay_worker.stop()
                logger.info("replay_worker_stopped")

        async def _shutdown_database() -> None:
            await dispose_engine()
            from redforge.api.dependencies import clear_cached_dependencies

            clear_cached_dependencies()
            logger.info("database_engine_disposed")

        async def _shutdown_behavior_detection_worker() -> None:
            worker = getattr(runtime, "behavior_detection_worker", None)
            if worker is not None:
                await worker.stop()
                logger.info("behavior_detection_worker_stopped")

        async def _shutdown_correlation_worker() -> None:
            worker = getattr(runtime, "correlation_worker", None)
            if worker is not None:
                await worker.stop()
                logger.info("correlation_worker_stopped")

        async def _shutdown_feed_sync_scheduler() -> None:
            worker = getattr(runtime, "feed_sync_scheduler", None)
            if worker is not None:
                await worker.stop()
                logger.info("feed_sync_scheduler_stopped")

        def _make_tenant_periodic_shutdown(runtime_attr: str) -> Any:
            async def _shutdown() -> None:
                runner = getattr(runtime, runtime_attr, None)
                if runner is not None:
                    await runner.stop()
                    logger.info(f"{runtime_attr}_stopped")

            return _shutdown

        _tenant_periodic_runner_names = (
            "analytics_scheduler_runner",
            "automated_action_scheduler_runner",
            "autonomous_intelligence_scheduler_runner",
            "exposure_reporting_scheduler_runner",
            "ioc_expiry_scheduler_runner",
            "incident_scheduler_runner",
            "playbook_scheduler_runner",
            "posture_forecasting_scheduler_runner",
            "regulatory_notification_scheduler_runner",
            "reporting_scheduler_runner",
            "threat_hunt_scheduler_runner",
            "integration_hub_scheduler_runner",
        )
        for _runner_attr in _tenant_periodic_runner_names:
            coordinator.register_shutdown(
                _runner_attr,
                _make_tenant_periodic_shutdown(_runner_attr),
                timeout_s=settings.runtime_shutdown_timeout_s,
            )

        coordinator.register_shutdown(
            "credential_vault_workers",
            _shutdown_credential_vault_workers,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "feed_sync_scheduler",
            _shutdown_feed_sync_scheduler,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "correlation_worker",
            _shutdown_correlation_worker,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "behavior_detection_worker",
            _shutdown_behavior_detection_worker,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "ddos_detection_worker",
            _shutdown_ddos_detection_worker,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "network_monitoring_scheduler",
            _shutdown_network_monitoring_scheduler,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "runtime_health_transition_worker",
            _shutdown_runtime_health_transition_worker,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "continuous_validation_scheduler",
            _shutdown_continuous_validation_scheduler,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "replay_worker",
            _shutdown_replay_worker,
            timeout_s=settings.runtime_shutdown_timeout_s,
        )
        coordinator.register_shutdown(
            "database", _shutdown_database, timeout_s=settings.runtime_shutdown_timeout_s
        )

        await coordinator.startup()
        logger.info(
            "application_startup",
            app_name=settings.app_name,
            version=settings.app_version,
            environment=settings.environment,
        )

        yield

        await coordinator.shutdown(timeout_s=settings.runtime_shutdown_timeout_s)
        logger.info("application_shutdown")

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "AIVAR RedForge — Continuous AI Security Validation Platform. "
            "Validates LLM applications, AI agents, RAG systems, MCP servers, "
            "and AI APIs through automated red teaming and security testing."
        ),
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        license_info={"name": "Proprietary"},
        contact={"name": "AIVAR Engineering", "email": "engineering@aivar.io"},
        lifespan=lifespan,
    )

    _register_middleware(app)
    _register_routers(app, settings)

    from attack_pattern_intel.api.exception_handlers import (
        register_attack_pattern_intel_exception_handlers,
    )
    from attack_surface_management.api.exception_handlers import (
        register_attack_surface_management_exception_handlers,
    )
    from campaign_intel.api.exception_handlers import (
        register_campaign_intel_exception_handlers,
    )
    from credential_vault.api.exception_handlers import register_credential_vault_exception_handlers
    from detection.api.exception_handlers import register_detection_exception_handlers
    from engagement.api.exception_handlers import register_engagement_exception_handlers
    from evidence.api.exception_handlers import register_evidence_exception_handlers
    from execution.api.exception_handlers import register_execution_exception_handlers
    from infrastructure_intel.api.exception_handlers import (
        register_infrastructure_intel_exception_handlers,
    )
    from intelligence_relationships.api.exception_handlers import (
        register_intelligence_relationships_exception_handlers,
    )
    from ioc_intelligence.api.exception_handlers import (
        register_ioc_intelligence_exception_handlers,
    )
    from malware_intel.api.exception_handlers import (
        register_malware_intel_exception_handlers,
    )
    from operation.api.exception_handlers import register_operation_exception_handlers
    from payload.api.exception_handlers import register_payload_exception_handlers
    from red_team_operator.api.exception_handlers import register_operator_exception_handlers
    from risk_engine.api.exception_handlers import register_risk_engine_exception_handlers
    from threat_actor_intel.api.exception_handlers import (
        register_threat_actor_intel_exception_handlers,
    )
    from threat_report_intel.api.exception_handlers import (
        register_threat_report_intel_exception_handlers,
    )
    from tool_intel.api.exception_handlers import (
        register_tool_intel_exception_handlers,
    )
    from vulnerability.api.exception_handlers import register_vulnerability_exception_handlers
    from vulnerability.api.scanning.exception_handlers import (
        register_scanning_exception_handlers,
    )

    register_credential_vault_exception_handlers(app)
    register_vulnerability_exception_handlers(app)
    register_scanning_exception_handlers(app)
    register_detection_exception_handlers(app)
    register_engagement_exception_handlers(app)
    register_operation_exception_handlers(app)
    register_execution_exception_handlers(app)
    register_operator_exception_handlers(app)
    register_evidence_exception_handlers(app)
    register_payload_exception_handlers(app)
    register_risk_engine_exception_handlers(app)
    register_threat_actor_intel_exception_handlers(app)
    register_ioc_intelligence_exception_handlers(app)
    register_attack_pattern_intel_exception_handlers(app)
    register_intelligence_relationships_exception_handlers(app)
    register_malware_intel_exception_handlers(app)
    register_campaign_intel_exception_handlers(app)
    register_tool_intel_exception_handlers(app)
    register_infrastructure_intel_exception_handlers(app)
    register_threat_report_intel_exception_handlers(app)
    register_attack_surface_management_exception_handlers(app)

    # Configure OpenTelemetry (after app creation so auto-instrumentation works)
    from redforge.infrastructure.telemetry import configure_telemetry

    configure_telemetry(
        app,
        enabled=settings.otel_enabled,
        service_name=settings.otel_service_name,
        otlp_endpoint=settings.otel_endpoint or None,
    )

    return app


def _register_middleware(app: FastAPI) -> None:
    """Register middleware in execution order (last added executes first).

    Order matters:
    1. ErrorHandler wraps everything — catches exceptions from all layers.
    2. RequestLogging logs the final status code (after error handling).
    3. Correlation injects IDs before any logging occurs.
    4. CORS handles preflight and response headers.
    """
    settings = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Correlation-ID"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CorrelationMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, limiter=InMemorySlidingWindowLimiter())
    app.add_middleware(PrometheusMiddleware)
    app.add_middleware(ErrorHandlerMiddleware)


def _register_routers(app: FastAPI, settings: Settings) -> None:
    """Register all API routers for `settings.product_edition` (ADR-0009).
    "full" mounts every route, identical to pre-edition behavior; any
    other edition mounts only its allow-listed subset — see
    `redforge.api.v1.build_v1_router`/`NETWORK_DEFENSE_TAGS`."""
    app.include_router(build_root_router(settings.product_edition))

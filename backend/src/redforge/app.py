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

from redforge.api.router import root_router
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
                sf, execution_policy_service, ai_target_service, asset_service,  # type: ignore[arg-type]
                condition_service, default_adaptive_rule_registry(), correlation_service,
                default_protocol_validator_registry(),
            )
            drift_service = SecurityDriftService(sf)
            processor = ContinuousValidationProcessor(
                sf, execution_service, ai_target_service, asset_service,
                condition_service, correlation_service, drift_service,
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
                sf, asset_service, condition_service, correlation_service,
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
        coordinator.register_startup("replay_worker", _start_replay_worker)
        coordinator.register_startup(
            "continuous_validation_scheduler", _start_continuous_validation_scheduler,
        )
        coordinator.register_startup(
            "runtime_health_transition_worker", _start_runtime_health_transition_worker,
        )
        coordinator.register_startup(
            "network_monitoring_scheduler", _start_network_monitoring_scheduler,
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
    _register_routers(app)

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


def _register_routers(app: FastAPI) -> None:
    """Register all API routers."""
    app.include_router(root_router)

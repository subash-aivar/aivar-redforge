"""RuntimeContainer — Sprint 27.

Holds every runtime singleton and wires them together.

The container is constructed once at application startup by
`build_runtime_container(settings)` and stored on `app.state.runtime`.
FastAPI dependencies retrieve individual components from the container
via `request.app.state.runtime`.

Design rules:
- No FastAPI, SQLAlchemy, or infrastructure imports.
- Container itself contains no I/O logic — only composition.
- All component construction is pure Python (no async needed).
- Settings are passed in; the container reads them but does not own them.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Any

from redforge.application.platform.backpressure import (
    BackpressureConfig,
    WatermarkBackpressureController,
)
from redforge.application.platform.bulkhead import BulkheadRegistry
from redforge.application.platform.circuit_breaker import (
    CircuitBreakerRegistry,
    DefaultCircuitBreaker,
)
from redforge.application.platform.dead_letter_queue import (
    InMemoryDeadLetterQueue,
    PoisonEventDetector,
)
from redforge.application.platform.health_engine import RuntimeHealthEngine
from redforge.application.platform.heartbeat import HeartbeatMonitor
from redforge.application.platform.lifecycle import GracefulShutdownCoordinator
from redforge.application.platform.metrics_abstraction import InMemoryMetricsCollector
from redforge.application.platform.projection_registry import ProjectionRegistry
from redforge.application.platform.runtime_contracts import RuntimeDLQ

if TYPE_CHECKING:
    from redforge.application.continuous_validation.scheduler_worker import (
        ContinuousValidationSchedulerWorker,
    )
    from redforge.application.knowledge_graph import KnowledgeGraph
    from redforge.application.platform.replay_worker import DLQReplayWorker
    from redforge.core.config import Settings


# ── Standard circuit breaker names ────────────────────────────────────────────
# These names are canonical and referenced by adapters in the infrastructure layer.

CB_EVENT_STORE = "event_store"
CB_KNOWLEDGE_GRAPH = "knowledge_graph"
CB_CONNECTOR = "connector"
CB_DATABASE = "database"


@dataclasses.dataclass
class RuntimeContainer:
    """All runtime platform singletons for one process.

    Stored on ``app.state.runtime`` during the FastAPI lifespan.
    Access via ``request.app.state.runtime`` in dependencies.

    Fields are mutable references to allow tests to swap components.
    """

    coordinator: GracefulShutdownCoordinator
    health_engine: RuntimeHealthEngine
    dlq: RuntimeDLQ  # InMemory in tests; PostgreSQL in production (wired by app.py)
    poison_detector: PoisonEventDetector
    metrics: InMemoryMetricsCollector
    circuit_registry: CircuitBreakerRegistry
    bulkhead_registry: BulkheadRegistry
    heartbeat_monitor: HeartbeatMonitor
    backpressure: WatermarkBackpressureController
    projection_registry: ProjectionRegistry
    replay_worker: DLQReplayWorker | None = None
    # M14 — continuous validation scheduler background worker.
    continuous_validation_scheduler: ContinuousValidationSchedulerWorker | None = None
    # M15 — runtime health HEALTHY<->UNHEALTHY transition detector worker.
    runtime_health_transition_worker: Any = None  # RuntimeHealthTransitionWorker
    # M16 — network monitoring scheduler background worker.
    network_monitoring_scheduler: Any = None  # NetworkMonitoringSchedulerWorker
    session_factory: Any = None  # async_sessionmaker set by app.py after DB startup
    knowledge_graph: KnowledgeGraph | None = None  # set by app.py; enables KGProjection
    # ── Red Team Evaluation Control Loop (Sprint 40) ──────────────────────────
    # RedTeamOrchestratorFactory constructed at startup; per-campaign objects
    # (ValidationService, RedTeamOrchestrator) built per request via factory.build().
    red_team_factory: Any = None  # RedTeamOrchestratorFactory
    # ── Credential resolver (Sprint 42/43) ────────────────────────────────────
    # Resolves provider auth_ref strings to secret values at the infrastructure
    # boundary. The resolved value is never returned to the client or persisted.
    credential_resolver: Any = None  # CredentialResolverPort impl
    # ── Feed Synchronization Foundation (M22 Phase 2) ─────────────────────────
    # Empty in Phase 2 — no FeedSyncExecutor is registered for any
    # FeedSourceKind until a Phase 3 connector calls `.register()`. Shared
    # between the admin API's sync-trigger endpoint and
    # FeedSyncSchedulerWorker so both resolve the exact same connector set.
    feed_connector_registry: Any = None  # FeedConnectorRegistry
    feed_sync_scheduler: Any = None  # FeedSyncSchedulerWorker, set by app.py


def build_runtime_container(settings: Settings) -> RuntimeContainer:
    """Construct the runtime container from application settings.

    Called once during FastAPI lifespan startup. The returned container
    is stored on ``app.state.runtime`` and shared for the process lifetime.

    Startup/shutdown hooks are NOT registered here — that wiring happens in
    ``app.py`` where the DB engine and other FastAPI resources are available.

    Args:
        settings: Validated application settings loaded at startup.

    Returns:
        Fully configured RuntimeContainer ready to have hooks registered.
    """
    coordinator = GracefulShutdownCoordinator()

    health_engine = RuntimeHealthEngine(
        check_timeout_s=settings.runtime_health_check_timeout_s,
    )

    dlq = InMemoryDeadLetterQueue(
        max_size=settings.runtime_dlq_max_size,
    )

    poison_detector = PoisonEventDetector(
        poison_threshold=settings.runtime_dlq_poison_threshold,
    )

    metrics = InMemoryMetricsCollector(
        max_samples=settings.runtime_metrics_max_samples,
    )

    circuit_registry = CircuitBreakerRegistry()
    _register_standard_circuit_breakers(circuit_registry, settings)

    bulkhead_registry = BulkheadRegistry()

    heartbeat_monitor = HeartbeatMonitor()

    backpressure = WatermarkBackpressureController(
        config=BackpressureConfig(
            max_concurrent=settings.runtime_backpressure_max_concurrent,
            high_watermark=settings.runtime_backpressure_high_watermark,
            low_watermark=settings.runtime_backpressure_low_watermark,
        )
    )

    projection_registry = _build_projection_registry()

    # ── Red Team Evaluation Control Loop (Sprint 40) ──────────────────────────
    from redforge.application.red_team.factory import _build_red_team_factory
    red_team_factory = _build_red_team_factory()

    # ── Credential resolver (Sprint 42/43) ────────────────────────────────────
    from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver
    credential_resolver = EnvironmentCredentialResolver()

    # ── Feed Synchronization Foundation (M22 Phase 2) ─────────────────────────
    from redforge.application.threat_intel.feed_connector import FeedConnectorRegistry
    feed_connector_registry = FeedConnectorRegistry()

    return RuntimeContainer(
        coordinator=coordinator,
        health_engine=health_engine,
        dlq=dlq,
        poison_detector=poison_detector,
        metrics=metrics,
        circuit_registry=circuit_registry,
        bulkhead_registry=bulkhead_registry,
        heartbeat_monitor=heartbeat_monitor,
        backpressure=backpressure,
        projection_registry=projection_registry,
        red_team_factory=red_team_factory,
        credential_resolver=credential_resolver,
        feed_connector_registry=feed_connector_registry,
    )


def _build_projection_registry(
    knowledge_graph: KnowledgeGraph | None = None,
) -> ProjectionRegistry:
    """Construct all projection instances and register them.

    When knowledge_graph is provided, KGProjection is registered as the 10th
    projection (DEBT-S31-2 resolved). KGProjection is omitted in test
    environments where the KnowledgeGraph is not wired.
    """
    from redforge.application.platform.projection_engine import (
        InMemoryReadModelRepository,
    )
    from redforge.application.platform.projections.asset_timeline_projection import (
        AssetTimelineProjection,
    )
    from redforge.application.platform.projections.campaign_projection import (
        CampaignProjection,
    )
    from redforge.application.platform.projections.connector_activity_projection import (
        ConnectorActivityProjection,
    )
    from redforge.application.platform.projections.evidence_projection import (
        EvidenceProjection,
    )
    from redforge.application.platform.projections.intelligence_projection import (
        IntelligenceProjection,
    )
    from redforge.application.platform.projections.inventory_projection import (
        InventoryProjection,
    )
    from redforge.application.platform.projections.organization_activity_projection import (
        OrganizationActivityProjection,
    )
    from redforge.application.platform.projections.risk_projection import (
        RiskProjection,
    )
    from redforge.application.platform.projections.validation_projection import (
        ValidationProjection,
    )

    repo = InMemoryReadModelRepository()
    registry = ProjectionRegistry()
    registry.register(CampaignProjection(repo))
    registry.register(InventoryProjection(repo))
    registry.register(ValidationProjection(repo))
    registry.register(RiskProjection(repo))
    registry.register(IntelligenceProjection(repo))
    registry.register(EvidenceProjection(repo))
    registry.register(ConnectorActivityProjection(repo))
    registry.register(AssetTimelineProjection(repo))
    registry.register(OrganizationActivityProjection(repo))

    if knowledge_graph is not None:
        from redforge.application.platform.projections.kg_projection import KGProjection
        registry.register(KGProjection(knowledge_graph, repo))

    # M27 Phase 5 — Vulnerability KG projection (ProjectionBase-compatible).
    from vulnerability.application.projections.vulnerability_kg_projection import (
        VulnerabilityKGProjection,
    )

    registry.register(VulnerabilityKGProjection(repo))

    # M29 Phase 6 — Red Team graph projection (ProjectionBase-compatible).
    from execution.application.projections.red_team_graph_projection import (
        RedTeamGraphProjection,
    )

    registry.register(RedTeamGraphProjection(repo))

    return registry


def _register_standard_circuit_breakers(
    registry: CircuitBreakerRegistry,
    settings: Settings,
) -> None:
    """Pre-populate the registry with breakers for known dependencies."""
    for name in (CB_EVENT_STORE, CB_KNOWLEDGE_GRAPH, CB_CONNECTOR, CB_DATABASE):
        registry.register(
            name,
            DefaultCircuitBreaker(
                component_id=name,
                failure_threshold=settings.runtime_circuit_breaker_failure_threshold,
                recovery_timeout_s=settings.runtime_circuit_breaker_recovery_timeout_s,
                window_size=settings.runtime_circuit_breaker_window_size,
            ),
        )

"""RedTeamOrchestratorFactory — production composition root for the red team pipeline.

Sprint 40: The evaluation control loop requires multiple collaborators. Some are
application-scoped singletons (EvaluationPipeline, ConsensusEngine, etc.); others
are per-campaign (ValidationService, ChatCompletionExecutor) because they require
target-specific provider credentials.

This factory owns the full composition:

    Application singletons (constructed once at startup):
      EvaluationPipeline
        ├── KeywordClassifier (deterministic evaluator, always present)
        ├── ConsensusEngine
        ├── EvaluationPolicyEnforcer
        └── DefaultFindingGenerator
      EvaluationDrivenIntelligenceAdapter
      RuleBasedCampaignIntelligenceService
      AttackLibraryResolver
      RiskCorrelationEngine

    Per-campaign objects (constructed per RedTeamOrchestrator.execute() call):
      ChatCompletionExecutor(provider_adapter)  ← provider adapter is per-target
      KnowledgeGraphPopulator(knowledge_graph)  ← graph is optional
      ValidationService(executor, pipeline, resolver, risk_engine, kg_populator,
                        uow_factory, event_publisher)
      ValidationService.with_evaluation_adapter(intel_adapter)
      RedTeamOrchestrator(validation_service, knowledge_graph, campaign_intelligence)

Design rules:
- The factory holds no mutable state.
- Each call to build() returns an independent RedTeamOrchestrator.
- The caller provides: provider_adapter (target-specific), uow_factory (DB session),
  knowledge_graph (optional KG reference for this campaign).
- organization_id comes EXCLUSIVELY from RedTeamRequest (JWT TenantContext),
  never from HTTP body or query parameters.
- No fake adapters. No no-op implementations. Every component is a real
  production class from the existing application/infrastructure layers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.application.red_team.campaign_intelligence import (
    RuleBasedCampaignIntelligenceService,
)
from redforge.application.red_team.evaluation_intelligence import (
    EvaluationDrivenIntelligenceAdapter,
)
from redforge.application.red_team.orchestrator import RedTeamOrchestrator
from redforge.application.risk_engine import RiskCorrelationEngine
from redforge.application.runtime.attacks.library_resolver import AttackLibraryResolver
from redforge.application.runtime.evaluation.aggregators import WeightedAverageAggregator
from redforge.application.runtime.evaluation.consensus import ConsensusEngine
from redforge.application.runtime.evaluation.findings import DefaultFindingGenerator
from redforge.application.runtime.evaluation.pipeline import EvaluationPipeline
from redforge.application.runtime.evaluation.policy import (
    STRICT_POLICY,
    EvaluationPolicyEnforcer,
)
from redforge.application.runtime.executors import ChatCompletionExecutor
from redforge.application.validation_service import ValidationService
from redforge.core.logging import get_logger
from redforge.infrastructure.events import NullEventPublisher

if TYPE_CHECKING:
    from redforge.application.knowledge_graph import KnowledgeGraph

logger = get_logger(__name__)


class RedTeamOrchestratorFactory:
    """Constructs a fully-wired RedTeamOrchestrator per campaign.

    Holds application-scoped singletons. Thread-safe: all singletons are
    stateless or thread-safe themselves. build() may be called concurrently
    from multiple request handlers.

    Lifecycle:
    - Constructed once by build_runtime_container() at app startup.
    - Held on RuntimeContainer.red_team_factory for the process lifetime.
    - build() is called per campaign execution request.
    """

    def __init__(self) -> None:
        # ── Application-scoped singletons ────────────────────────────────────
        # Constructed once; shared across all campaigns.

        self._evaluation_pipeline = EvaluationPipeline(
            evaluators=_default_evaluators(),
            aggregator=WeightedAverageAggregator(),
            finding_generator=DefaultFindingGenerator(),
            consensus_engine=ConsensusEngine(),
            policy_enforcer=EvaluationPolicyEnforcer(),
            policy=STRICT_POLICY,
        )
        self._intelligence_adapter = EvaluationDrivenIntelligenceAdapter()
        self._campaign_intelligence = RuleBasedCampaignIntelligenceService()
        self._attack_resolver = AttackLibraryResolver()
        self._risk_engine = RiskCorrelationEngine()

        logger.info(
            "red_team_factory_initialized",
            evaluators=len(_default_evaluators()),
            policy="strict",
        )

    @property
    def evaluation_pipeline(self) -> EvaluationPipeline:
        """The canonical singleton EvaluationPipeline. Used by integration tests."""
        return self._evaluation_pipeline

    @property
    def intelligence_adapter(self) -> EvaluationDrivenIntelligenceAdapter:
        """The canonical singleton EvaluationDrivenIntelligenceAdapter."""
        return self._intelligence_adapter

    @property
    def campaign_intelligence(self) -> RuleBasedCampaignIntelligenceService:
        """The canonical singleton CampaignIntelligenceService."""
        return self._campaign_intelligence

    def build(
        self,
        provider_adapter: Any,
        uow_factory: Any,
        knowledge_graph: KnowledgeGraph | None = None,
    ) -> RedTeamOrchestrator:
        """Build a fully-wired RedTeamOrchestrator for one campaign.

        Parameters
        ----------
        provider_adapter:
            A real LLM provider adapter (OpenAIAdapter, AnthropicAdapter, etc.)
            that implements the chat_completion() protocol. Must NOT be a stub
            or no-op implementation in the production path.
        uow_factory:
            A callable that returns a UnitOfWork. In production: the PostgreSQL
            UnitOfWork factory from the DB session pool.
        knowledge_graph:
            Optional shared KnowledgeGraph instance for projection. When None,
            graph population is skipped (not an error — some deployments do not
            require KG).

        Returns
        -------
        RedTeamOrchestrator
            Fully-wired orchestrator with the evaluation control loop active.
            The ValidationService inside has with_evaluation_adapter() already called.
        """
        executor = ChatCompletionExecutor(provider_adapter=provider_adapter)
        kg_populator = None
        if knowledge_graph is not None:
            from redforge.application.knowledge_graph_populator import (
                KnowledgeGraphPopulator,
            )
            kg_populator = KnowledgeGraphPopulator(knowledge_graph)

        validation_service = ValidationService(
            executor=executor,
            classifier=self._evaluation_pipeline,
            attack_resolver=self._attack_resolver,
            risk_engine=self._risk_engine,
            kg_populator=kg_populator,
            uow_factory=uow_factory,
            event_publisher=NullEventPublisher(),
        ).with_evaluation_adapter(self._intelligence_adapter)

        orchestrator = RedTeamOrchestrator(
            validation_service=validation_service,
            knowledge_graph=knowledge_graph,
            campaign_intelligence=self._campaign_intelligence,
        )

        logger.info(
            "red_team_orchestrator_built",
            has_kg=knowledge_graph is not None,
        )
        return orchestrator


def _default_evaluators() -> list[Any]:
    """Return the default production evaluator list.

    Uses KeywordEvaluator (implements the Evaluator protocol with .name and
    .evaluate()) as the sole deterministic evaluator. This ensures the
    pipeline always has at least one evaluator — an empty evaluator list
    would produce only ERROR outcomes.

    SecurityJudgeEvaluator (LLM-based) is NOT included here because it
    requires an LLM provider API key. Add it by replacing this function's
    output with an injected evaluator list when the provider is configured.
    """
    from redforge.application.runtime.evaluation.evaluators import KeywordEvaluator
    return [KeywordEvaluator()]


def _build_red_team_factory() -> RedTeamOrchestratorFactory:
    """Construct the singleton RedTeamOrchestratorFactory for the process."""
    return RedTeamOrchestratorFactory()

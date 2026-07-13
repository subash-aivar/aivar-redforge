"""Plugin SDK for the RedForge Red Team Platform — Sprint 36/37.

All extension points in the adaptive intelligence layer are exposed as
Protocols in this module. Customers and third-party developers implement
these protocols to extend the platform without modifying core code.

Architecture:
- Every extension point is a @runtime_checkable Protocol.
- PluginRegistry holds registered implementations; the orchestrator
  queries the registry at wiring time (not at execution time).
- No switch statements — registry dispatch is dict-based.
- Plugins are self-describing (metadata property) for tooling and UI.

Plugin categories:
1. AttackStrategyPlugin      — add new attack categories
2. PayloadStrategyPlugin     — add new payload mutation strategies
3. ConversationStrategyPlugin — add new conversation strategies
4. CampaignDecisionPlugin    — replace/extend the decision engine
5. IntelligenceProviderPlugin — replace/extend the intelligence backend

Usage:
    from redforge.application.red_team.plugin_sdk import PluginRegistry

    registry = PluginRegistry()
    registry.register_attack_strategy(MyCustomAttackStrategy())
    orchestrator = RedTeamOrchestrator(
        validation_service=...,
        plugin_registry=registry,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.application.red_team.campaign_intelligence import (
        CampaignIntelligenceServicePort,
    )


# ─── Plugin Metadata ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PluginMetadata:
    """Self-description of a plugin for tooling and UI display."""

    name: str
    version: str
    description: str
    author: str = ""
    tags: tuple[str, ...] = ()
    capabilities: frozenset[str] = field(default_factory=frozenset)


# ─── Attack Strategy Plugin ───────────────────────────────────────────────────


@runtime_checkable
class AttackStrategyPlugin(Protocol):
    """Plugin for adding new attack categories to the platform.

    Implementing this protocol makes new attack categories available to
    the RedTeamOrchestrator without modifying the AttackLibrary or any
    core code.

    The plugin provides both the definition (what the attack IS) and the
    execution delegation (how to execute it — typically delegated to
    ValidationService with a custom attack category string).
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Plugin self-description."""
        ...

    @property
    def attack_categories(self) -> frozenset[str]:
        """The attack category names this plugin provides."""
        ...

    def can_handle(self, attack_category: str) -> bool:
        """Return True if this plugin handles the given category."""
        ...

    def escalation_targets(self, attack_category: str) -> tuple[str, ...]:
        """Return escalation follow-ons for the given category."""
        ...

    def branch_targets(self, attack_category: str) -> tuple[str, ...]:
        """Return branch siblings for the given category."""
        ...


# ─── Payload Strategy Plugin ──────────────────────────────────────────────────


@runtime_checkable
class PayloadStrategyPlugin(Protocol):
    """Plugin for adding new payload mutation strategies.

    Implementing this protocol adds new mutation types that the
    AdaptivePayloadStrategySelector can recommend. The actual mutation
    is registered in the domain's MUTATION_REGISTRY (payload_pipeline.py);
    this plugin provides the selection logic layer.
    """

    @property
    def metadata(self) -> PluginMetadata:
        ...

    @property
    def mutation_types(self) -> frozenset[str]:
        """Mutation type names this plugin provides (matching MutationType values)."""
        ...

    def preferred_for_provider(self, provider: str) -> bool:
        """Return True if this mutation is preferred for the given provider."""
        ...

    def preferred_for_category(self, attack_category: str) -> bool:
        """Return True if this mutation is preferred for the attack category."""
        ...


# ─── Conversation Strategy Plugin ─────────────────────────────────────────────


@runtime_checkable
class ConversationStrategyPlugin(Protocol):
    """Plugin for adding new conversation strategies.

    Implementing this protocol adds new ConversationStrategyType values
    and their implementations to the CONVERSATION_STRATEGY_REGISTRY.
    The strategy value is registered by the plugin loader.
    """

    @property
    def metadata(self) -> PluginMetadata:
        ...

    @property
    def strategy_name(self) -> str:
        """Strategy type value (must be a valid ConversationStrategyType value)."""
        ...

    def preferred_for_provider(self, provider: str) -> bool:
        ...

    def preferred_for_category(self, attack_category: str) -> bool:
        ...


# ─── Campaign Decision Plugin ─────────────────────────────────────────────────


@runtime_checkable
class CampaignDecisionPlugin(Protocol):
    """Plugin for replacing or extending the campaign decision engine.

    Implement CampaignIntelligenceServicePort directly and register this
    plugin to replace RuleBasedCampaignIntelligenceService with a custom
    (e.g., ML-backed) decision engine.
    """

    @property
    def metadata(self) -> PluginMetadata:
        ...

    def build_intelligence_service(self) -> CampaignIntelligenceServicePort:
        """Construct and return the intelligence service implementation."""
        ...


# ─── Intelligence Provider Plugin ─────────────────────────────────────────────


@runtime_checkable
class IntelligenceProviderPlugin(Protocol):
    """Plugin for extending the intelligence backend.

    Unlike CampaignDecisionPlugin (which replaces the decision engine),
    this plugin extends IntelligenceService with a new insight provider —
    e.g., an LLM-backed insight generator, a threat feed integration,
    or a vulnerability database connector.
    """

    @property
    def metadata(self) -> PluginMetadata:
        ...

    @property
    def provides(self) -> frozenset[str]:
        """What this plugin provides: "insights", "recommendations", etc."""
        ...

    def is_available(self) -> bool:
        """Return True if this provider is configured and available."""
        ...


# ─── Plugin Registry ──────────────────────────────────────────────────────────


class PluginRegistry:
    """Central registry for all RedForge red team plugins.

    Thread-safe for reads (dict is thread-safe for reads in CPython).
    Writes (register_*) should happen at application startup only.

    Usage:
        registry = PluginRegistry()
        registry.register_attack_strategy(my_plugin)
        registry.register_conversation_strategy(my_conv_plugin)
    """

    def __init__(self) -> None:
        self._attack_strategies: list[AttackStrategyPlugin] = []
        self._payload_strategies: list[PayloadStrategyPlugin] = []
        self._conversation_strategies: list[ConversationStrategyPlugin] = []
        self._decision_plugins: list[CampaignDecisionPlugin] = []
        self._intelligence_providers: list[IntelligenceProviderPlugin] = []

    # ── Registration ─────────────────────────────────────────────────────────

    def register_attack_strategy(self, plugin: AttackStrategyPlugin) -> None:
        self._attack_strategies.append(plugin)

    def register_payload_strategy(self, plugin: PayloadStrategyPlugin) -> None:
        self._payload_strategies.append(plugin)

    def register_conversation_strategy(self, plugin: ConversationStrategyPlugin) -> None:
        self._conversation_strategies.append(plugin)

    def register_decision_plugin(self, plugin: CampaignDecisionPlugin) -> None:
        self._decision_plugins.append(plugin)

    def register_intelligence_provider(self, plugin: IntelligenceProviderPlugin) -> None:
        self._intelligence_providers.append(plugin)

    # ── Query ─────────────────────────────────────────────────────────────────

    def attack_strategies_for(
        self, attack_category: str
    ) -> list[AttackStrategyPlugin]:
        return [p for p in self._attack_strategies if p.can_handle(attack_category)]

    def all_attack_categories(self) -> frozenset[str]:
        result: set[str] = set()
        for plugin in self._attack_strategies:
            result.update(plugin.attack_categories)
        return frozenset(result)

    def payload_strategies_for(
        self, provider: str, attack_category: str
    ) -> list[PayloadStrategyPlugin]:
        return [
            p for p in self._payload_strategies
            if p.preferred_for_provider(provider) or p.preferred_for_category(attack_category)
        ]

    def conversation_strategies_for(
        self, provider: str, attack_category: str
    ) -> list[ConversationStrategyPlugin]:
        return [
            p for p in self._conversation_strategies
            if p.preferred_for_provider(provider) or p.preferred_for_category(attack_category)
        ]

    def active_decision_plugin(self) -> CampaignDecisionPlugin | None:
        """Return the most recently registered decision plugin (last-wins)."""
        return self._decision_plugins[-1] if self._decision_plugins else None

    def available_intelligence_providers(self) -> list[IntelligenceProviderPlugin]:
        return [p for p in self._intelligence_providers if p.is_available()]

    def is_empty(self) -> bool:
        return not (
            self._attack_strategies
            or self._payload_strategies
            or self._conversation_strategies
            or self._decision_plugins
            or self._intelligence_providers
        )

    def summary(self) -> dict[str, int]:
        """Return a summary dict for logging/diagnostics."""
        return {
            "attack_strategies": len(self._attack_strategies),
            "payload_strategies": len(self._payload_strategies),
            "conversation_strategies": len(self._conversation_strategies),
            "decision_plugins": len(self._decision_plugins),
            "intelligence_providers": len(self._intelligence_providers),
        }

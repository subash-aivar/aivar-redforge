"""Adaptive strategy selectors for the Campaign Intelligence Layer — Sprint 36/37.

Three independent strategy selectors:
1. AdaptiveAttackSelector      — which attack categories to add next
2. AdaptivePayloadStrategySelector — which payload mutation to prefer
3. ConversationStrategySelector    — which ConversationStrategyType to use

All selectors are stateless and protocol-based. Default implementations
are rule-based and provider/category-aware. Custom implementations can
be injected via the plugin SDK.

Design rule: these selectors make RECOMMENDATIONS — they do not execute.
The orchestrator acts on their recommendations. All recommendations must
be deterministic given the same input (no randomness).
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable

from redforge.core.logging import get_logger

logger = get_logger(__name__)

# ─── Attack Category Selector ─────────────────────────────────────────────────

# Attack categories grouped by family — used for coherent attack selection
_CATEGORY_FAMILIES: dict[str, frozenset[str]] = {
    "injection": frozenset({
        "prompt_injection", "indirect_prompt_injection",
        "multi_modal_prompt_injection", "agent_chain_injection",
    }),
    "jailbreak": frozenset({
        "jailbreak", "role_play_jailbreak", "many_shot_jailbreak",
        "authority_escalation_jailbreak", "persona_theft",
    }),
    "exfiltration": frozenset({
        "data_exfiltration", "system_prompt_extraction",
        "training_data_extraction", "configuration_leakage",
        "secret_extraction", "side_channel_attacks",
    }),
    "agentic": frozenset({
        "agent_hijacking", "cross_agent_injection", "tool_misuse",
        "tool_chain_abuse", "mcp_tool_injection", "mcp_resource_hijack",
        "mcp_server_bypass",
    }),
    "rag": frozenset({
        "rag_poisoning", "vector_store_poisoning", "retrieval_manipulation",
    }),
    "multi_tenant": frozenset({
        "cross_context_injection", "tenant_boundary_violation",
        "session_confusion",
    }),
    "availability": frozenset({
        "model_denial_of_service", "resource_exhaustion", "prompt_flooding",
    }),
}


@runtime_checkable
class AdaptiveAttackSelectorPort(Protocol):
    """Selects next attack categories based on campaign context.

    The selector does NOT modify graph state — it returns a list of
    category names. The orchestrator decides whether/how to inject them.
    """

    def select_next(
        self,
        attack_category: str,
        already_run: frozenset[str],
        target_provider: str,
        finding_count: int,
        max_to_return: int,
    ) -> list[str]:
        """Return up to max_to_return category names not in already_run."""
        ...


class FamilyBasedAttackSelector:
    """Selects attack categories from the same family as the triggering category.

    When a category produces findings, explore its full family to validate
    the breadth of vulnerability exposure.
    """

    def select_next(
        self,
        attack_category: str,
        already_run: frozenset[str],
        target_provider: str,
        finding_count: int,
        max_to_return: int,
    ) -> list[str]:
        # Find which family this category belongs to
        family: frozenset[str] = frozenset()
        for fam_categories in _CATEGORY_FAMILIES.values():
            if attack_category in fam_categories:
                family = fam_categories
                break

        if not family:
            return []

        candidates = sorted(family - already_run - {attack_category})
        return candidates[:max_to_return]


# ─── Payload Strategy Selector ────────────────────────────────────────────────

# Per-provider preferred mutation order (most effective first, heuristic)
_PROVIDER_MUTATION_PREFERENCE: dict[str, list[str]] = {
    "openai": ["unicode", "zero_width", "base64", "whitespace", "markdown"],
    "anthropic": ["zero_width", "unicode", "typoglycemia", "whitespace", "base64"],
    "azure_openai": ["base64", "unicode", "html", "xml", "zero_width"],
    "bedrock": ["html", "xml", "unicode", "base64", "whitespace"],
    "vertex": ["typoglycemia", "unicode", "whitespace", "markdown", "zero_width"],
    "local": ["markdown", "json", "yaml", "unicode", "whitespace"],
}

_DEFAULT_MUTATION_ORDER = ["unicode", "base64", "zero_width", "whitespace", "markdown"]


@runtime_checkable
class AdaptivePayloadStrategySelectorPort(Protocol):
    """Selects the optimal payload mutation strategy for the next attempt.

    Returns a mutation type name (matching MutationType values in the
    payload domain). The caller is responsible for applying the mutation
    through the existing PayloadIntelligenceEngine pipeline.
    """

    def select_mutation(
        self,
        target_provider: str,
        attack_category: str,
        prior_mutations_tried: frozenset[str],
        consecutive_failures: int,
    ) -> str | None:
        """Return mutation type name or None (no mutation — use default)."""
        ...


class ProviderAwarePayloadStrategySelector:
    """Selects payload mutation based on provider profile and failure history.

    Cycles through the provider's preferred mutation order, skipping
    mutations already tried. Returns None when all options are exhausted.
    """

    def select_mutation(
        self,
        target_provider: str,
        attack_category: str,
        prior_mutations_tried: frozenset[str],
        consecutive_failures: int,
    ) -> str | None:
        preference = _PROVIDER_MUTATION_PREFERENCE.get(
            target_provider.lower(), _DEFAULT_MUTATION_ORDER
        )
        for mutation in preference:
            if mutation not in prior_mutations_tried:
                return mutation
        return None


# ─── Conversation Strategy Selector ──────────────────────────────────────────

# Per-attack-category preferred conversation strategy
_CATEGORY_STRATEGY_MAP: dict[str, str] = {
    "prompt_injection": "context_poisoning",
    "indirect_prompt_injection": "context_poisoning",
    "jailbreak": "progressive_escalation",
    "role_play_jailbreak": "role_play",
    "many_shot_jailbreak": "progressive_escalation",
    "authority_escalation_jailbreak": "authority_escalation",
    "data_exfiltration": "goal_refinement",
    "system_prompt_extraction": "recursive_prompting",
    "tool_misuse": "tool_discovery",
    "tool_chain_abuse": "tool_abuse_preparation",
    "mcp_tool_injection": "tool_abuse_preparation",
    "agent_hijacking": "goal_refinement",
    "cross_agent_injection": "context_poisoning",
    "rag_poisoning": "memory_manipulation",
    "model_denial_of_service": "progressive_escalation",
    "cross_context_injection": "context_poisoning",
}

# Per-provider overrides (provider preference takes priority when conflicts arise)
_PROVIDER_STRATEGY_OVERRIDE: dict[str, dict[str, str]] = {
    "anthropic": {
        "jailbreak": "recursive_prompting",
        "role_play_jailbreak": "progressive_escalation",
    },
    "openai": {
        "tool_misuse": "tool_abuse_preparation",
    },
}

_DEFAULT_STRATEGY = "progressive_escalation"


@runtime_checkable
class ConversationStrategySelectorPort(Protocol):
    """Selects the best ConversationStrategyType for a given attack.

    The returned string must match a ConversationStrategyType value.
    The caller passes this to ConversationEngine.run() via ConversationRequest.
    """

    def select_strategy(
        self,
        attack_category: str,
        target_provider: str,
        consecutive_failures: int,
        prior_strategies_tried: frozenset[str],
    ) -> str:
        """Return the strategy type value string."""
        ...


class CategoryProviderConversationStrategySelector:
    """Selects conversation strategy based on attack category + provider.

    Priority:
    1. Provider-specific override (if exists for this category+provider)
    2. Category-specific strategy
    3. Default (progressive_escalation)

    If the selected strategy has already been tried, cycles to the next
    available strategy.
    """

    # Fallback cycle order when preferred strategies are exhausted
    _FALLBACK_ORDER: ClassVar[list[str]] = [
        "progressive_escalation",
        "context_poisoning",
        "recursive_prompting",
        "role_play",
        "goal_refinement",
        "authority_escalation",
        "memory_manipulation",
        "reasoning_manipulation",
        "single_turn",
    ]

    def select_strategy(
        self,
        attack_category: str,
        target_provider: str,
        consecutive_failures: int,
        prior_strategies_tried: frozenset[str],
    ) -> str:
        # Check provider-specific override
        provider_overrides = _PROVIDER_STRATEGY_OVERRIDE.get(target_provider.lower(), {})
        preferred = provider_overrides.get(
            attack_category,
            _CATEGORY_STRATEGY_MAP.get(attack_category, _DEFAULT_STRATEGY),
        )

        if preferred not in prior_strategies_tried:
            return preferred

        # Cycle through fallback order
        for strategy in self._FALLBACK_ORDER:
            if strategy not in prior_strategies_tried:
                return strategy

        # All tried — reset and use default
        return _DEFAULT_STRATEGY

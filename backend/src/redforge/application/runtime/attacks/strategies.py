"""Attack execution strategy implementations.

SingleTurnStrategy: one prompt → one response → done.
This is the reference implementation. Future strategies:
- MultiTurnStrategy: escalating conversation
- AdaptiveStrategy: adjusts based on responses
- RecursiveStrategy: iteratively refines attacks
- AgentStrategy: autonomous multi-step agent attacks
"""

from __future__ import annotations

from redforge.application.runtime.attacks.context import AttackExecutionContext
from redforge.application.runtime.attacks.contracts import (
    AttackPlan,
    ConversationBuilder,
    PayloadGenerator,
    PromptRenderer,
)


class SingleTurnStrategy:
    """Single-turn attack strategy.

    Flow: generate payload → render → build conversation → done.
    One request, one response. Simplest possible attack pattern.

    Suitable for:
    - Prompt injection (direct)
    - Jailbreak (single attempt)
    - System prompt leakage (single probe)
    - Data exfiltration (single query)
    """

    async def plan(
        self,
        context: AttackExecutionContext,
        payload_generator: PayloadGenerator,
        renderer: PromptRenderer,
        conversation_builder: ConversationBuilder,
    ) -> AttackPlan:
        """Plan a single-turn attack."""
        # 1. Generate payload
        payload = await payload_generator.generate(context)

        # 2. Render template with variables
        rendered = renderer.render(payload.template_content, payload.variables)

        # 3. Build conversation
        conversation = conversation_builder.build(rendered, context)

        return AttackPlan(
            turns=[conversation],
            stop_condition="complete_all",
            max_turns=1,
            metadata={"strategy": "single_turn"},
        )

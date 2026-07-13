"""Integration adapter between Attack Execution Engine and Runtime.

Bridges the attack pipeline output (AttackPlan with Conversations)
to the existing runtime contracts (StepContext for StepExecutor).

This adapter does NOT modify the runtime. It translates attack engine
output into the format the runtime already understands.
"""

from __future__ import annotations

from redforge.application.runtime.attacks.context import AttackExecutionContext
from redforge.application.runtime.attacks.contracts import (
    AttackExecutionStrategy,
    AttackPlan,
    ConversationBuilder,
    PayloadGenerator,
    PromptRenderer,
)
from redforge.application.runtime.contracts import StepContext


class AttackPipelineRunner:
    """Runs the full attack pipeline and produces StepContexts.

    Coordinates: strategy → generator → renderer → builder → step contexts.

    This is the single integration point between the attack engine
    and the existing runtime execution pipeline.
    """

    def __init__(
        self,
        strategy: AttackExecutionStrategy,
        payload_generator: PayloadGenerator,
        renderer: PromptRenderer,
        conversation_builder: ConversationBuilder,
    ) -> None:
        self._strategy = strategy
        self._generator = payload_generator
        self._renderer = renderer
        self._builder = conversation_builder

    async def prepare(
        self, context: AttackExecutionContext
    ) -> list[StepContext]:
        """Run the attack pipeline and produce StepContexts for the runtime.

        Steps:
        1. Strategy plans the attack (produces conversations)
        2. Each conversation turn becomes a StepContext
        """
        plan = await self._strategy.plan(
            context,
            self._generator,
            self._renderer,
            self._builder,
        )

        return self._plan_to_step_contexts(plan, context)

    def _plan_to_step_contexts(
        self, plan: AttackPlan, context: AttackExecutionContext
    ) -> list[StepContext]:
        """Convert an AttackPlan into runtime StepContexts."""
        step_contexts: list[StepContext] = []

        for turn_index, conversation in enumerate(plan.turns):
            # Extract the user message content as the payload
            payload = conversation.last_user_message

            step_contexts.append(StepContext(
                step_id=f"{context.step_id}-turn-{turn_index}",
                attack_id=context.attack.attack_id,
                attack_name=context.attack.attack_name,
                target_id=context.target.target_id,
                target_endpoint=context.target.endpoint,
                target_provider=context.target.provider,
                payload_content=payload,
                timeout_seconds=context.options.timeout_seconds,
                metadata={
                    "turn_index": turn_index,
                    "total_turns": len(plan.turns),
                    "strategy": plan.metadata.get("strategy", "unknown"),
                    "messages": [
                        {"role": m.role, "content": m.content}
                        for m in conversation.messages
                    ],
                },
            ))

        return step_contexts

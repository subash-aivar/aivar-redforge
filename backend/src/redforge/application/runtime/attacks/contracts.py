"""Attack Execution Engine protocols.

Every component in the attack pipeline is protocol-based.
Customers can implement any of these to create proprietary attacks.

Pipeline:
    AttackExecutionStrategy.plan(context)
        → PayloadGenerator.generate(context)
            → PromptRenderer.render(template, variables)
                → ConversationBuilder.build(rendered_content, context)
                    → list[Message] ready for StepExecutor
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from redforge.application.runtime.attacks.context import AttackExecutionContext

# ─── Data Types ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Message:
    """A single message in a conversation (OpenAI-compatible format).

    Supports: system, user, assistant, tool, function roles.
    """

    role: str  # "system" | "user" | "assistant" | "tool" | "function"
    content: str
    name: str = ""
    tool_call_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Conversation:
    """An ordered sequence of messages forming a conversation.

    This is what gets dispatched to the provider adapter.
    Immutable — each turn produces a new Conversation.
    """

    messages: tuple[Message, ...]

    @property
    def message_count(self) -> int:
        return len(self.messages)

    @property
    def last_user_message(self) -> str:
        for msg in reversed(self.messages):
            if msg.role == "user":
                return msg.content
        return ""

    def with_message(self, message: Message) -> Conversation:
        """Return a new Conversation with an additional message appended."""
        return Conversation(messages=(*self.messages, message))


@dataclass(frozen=True, slots=True)
class GeneratedPayload:
    """Output of PayloadGenerator — content ready for rendering."""

    template_content: str
    variables: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackPlan:
    """Output of AttackExecutionStrategy — how to execute the attack.

    A plan consists of one or more turns. Each turn is a conversation
    to send. Single-turn attacks have exactly one turn.
    """

    turns: list[Conversation]
    stop_condition: str = "complete_all"  # "complete_all" | "first_success" | "max_turns"
    max_turns: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_single_turn(self) -> bool:
        return self.max_turns == 1 and len(self.turns) <= 1


# ─── Protocols ────────────────────────────────────────────────────────────────


@runtime_checkable
class PayloadGenerator(Protocol):
    """Generates or selects payload content for an attack.

    Input: AttackExecutionContext
    Output: GeneratedPayload (template + variables)

    Implementations:
    - StaticPayloadGenerator (fixed payloads from templates)
    - DynamicPayloadGenerator (context-aware generation)
    - Future: LLMPayloadGenerator (adversarial generation via LLM)
    """

    async def generate(self, context: AttackExecutionContext) -> GeneratedPayload:
        """Generate a payload for the given attack context."""
        ...


@runtime_checkable
class PromptRenderer(Protocol):
    """Renders template content with variables into final prompt text.

    Input: template string + variables dict
    Output: rendered string

    Implementations:
    - SimpleRenderer ({{ variable }} substitution)
    - Future: JinjaRenderer, sandboxed scripting
    """

    def render(self, template: str, variables: dict[str, str]) -> str:
        """Render a template with the given variables."""
        ...


@runtime_checkable
class ConversationBuilder(Protocol):
    """Builds a Conversation from rendered content and context.

    Input: rendered payload + context
    Output: Conversation (message array)

    Implementations:
    - SingleTurnBuilder (system + user message)
    - Future: MultiTurnBuilder, AgentBuilder, ToolUseBuilder
    """

    def build(
        self, rendered_content: str, context: AttackExecutionContext
    ) -> Conversation:
        """Construct a conversation from rendered content."""
        ...


@runtime_checkable
class AttackExecutionStrategy(Protocol):
    """Determines how an attack is executed (flow, sequencing, stopping).

    Input: AttackExecutionContext + pipeline components
    Output: AttackPlan (conversations to execute)

    Implementations:
    - SingleTurnStrategy (one prompt, one response)
    - Future: MultiTurnStrategy, AdaptiveStrategy, RecursiveStrategy
    """

    async def plan(
        self,
        context: AttackExecutionContext,
        payload_generator: PayloadGenerator,
        renderer: PromptRenderer,
        conversation_builder: ConversationBuilder,
    ) -> AttackPlan:
        """Plan the attack execution — produce conversations to send."""
        ...

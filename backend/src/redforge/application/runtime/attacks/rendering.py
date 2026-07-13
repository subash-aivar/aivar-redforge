"""Prompt rendering and conversation building implementations.

SimpleRenderer: {{ variable }} substitution (no logic, no code execution).
SingleTurnBuilder: constructs system + user message conversations.

Future:
- JinjaRenderer (complex templates with loops/conditionals)
- MultiTurnBuilder (escalating conversations)
- ToolUseBuilder (function calling message format)
- AgentBuilder (autonomous agent conversation structure)
"""

from __future__ import annotations

import re

from redforge.application.runtime.attacks.context import AttackExecutionContext
from redforge.application.runtime.attacks.contracts import Conversation, Message

_VAR_PATTERN = re.compile(r"\{\{\s*(\w+)\s*\}\}")


class SimpleRenderer:
    """Simple {{ variable }} template renderer.

    Replaces all {{ variable_name }} placeholders with values
    from the provided variables dict. Unresolved variables are
    left as-is (not removed, not errored).

    No code execution. No Jinja. No logic blocks.
    Designed for security: renders cannot execute arbitrary code.
    """

    def render(self, template: str, variables: dict[str, str]) -> str:
        """Render a template by substituting {{ var }} placeholders."""

        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            return variables.get(var_name, match.group(0))

        return _VAR_PATTERN.sub(_replace, template)


class SingleTurnBuilder:
    """Builds a single-turn conversation (system + user message).

    The simplest conversation structure:
    - System message (from target metadata or default)
    - User message (the attack payload)

    Future builders will support multi-turn, tool calls, etc.
    """

    def __init__(self, default_system_prompt: str = "") -> None:
        self._default_system = default_system_prompt

    def build(
        self, rendered_content: str, context: AttackExecutionContext
    ) -> Conversation:
        """Build a conversation with system prompt + user attack payload."""
        system_prompt = (
            context.target.system_prompt
            or self._default_system
            or "You are a helpful assistant."
        )

        messages: list[Message] = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=rendered_content),
        ]

        return Conversation(messages=tuple(messages))

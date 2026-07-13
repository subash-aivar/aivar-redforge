"""Step executor implementations.

Each executor handles a specific target interaction mode.
This module provides the ChatCompletionExecutor — the reference
implementation for LLM chat targets.

Future executors: ToolUseExecutor, AgentExecutor, RAGExecutor, MCPExecutor.
"""

from __future__ import annotations

import time
from typing import Any

from redforge.application.runtime.contracts import StepContext, StepEvidence
from redforge.core.logging import get_logger

logger = get_logger(__name__)


class ChatCompletionExecutor:
    """Executes attack steps against chat completion endpoints.

    Uses the existing provider adapter infrastructure.
    Captures the full request/response cycle as evidence.

    This executor:
    - Renders the payload into a chat message
    - Calls the provider adapter
    - Captures timing, request, and response
    - Returns immutable StepEvidence

    It does NOT:
    - Classify results (that's ResponseClassifier's job)
    - Generate findings
    - Update ValidationRun state
    """

    def __init__(
        self,
        provider_adapter: Any,  # ProviderAdapter protocol
        system_prompt: str = "You are a helpful assistant.",
        model: str | None = None,
    ) -> None:
        self._adapter = provider_adapter
        self._system_prompt = system_prompt
        self._model = model

    async def execute(self, context: StepContext) -> StepEvidence:
        """Execute a single chat completion attack step.

        Multi-turn conversations: callers (ConversationEngine) pack the full
        accumulated message list into context.metadata["messages"]. When
        present, that list is used verbatim so the target sees the complete
        conversation history, not just the latest user message.

        Single-turn callers (ValidationService) do not set metadata["messages"],
        so they get the default 2-message [system, user] format unchanged.

        The effective system prompt precedence:
          1. context.metadata["system_prompt"] (caller-specific override)
          2. self._system_prompt (executor construction-time default)
        """
        start = time.perf_counter()

        # Multi-turn path: caller supplies the full conversation history
        raw_messages: list[dict[str, Any]] | None = context.metadata.get("messages")
        if raw_messages:
            messages = raw_messages
        else:
            # Single-turn path: build the canonical 2-message array
            system_prompt = context.metadata.get("system_prompt", self._system_prompt)
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": context.payload_content},
            ]

        request_body = str(messages)

        try:
            model = self._model or context.metadata.get("model", "gpt-4")
            response = await self._adapter.chat_completion(messages, model)
            duration_ms = int((time.perf_counter() - start) * 1000)

            return StepEvidence(
                step_id=context.step_id,
                attack_id=context.attack_id,
                target_id=context.target_id,
                request_method="POST",
                request_url=context.target_endpoint,
                request_body=request_body,
                response_status=200,
                response_body=response.content,
                duration_ms=duration_ms,
                metadata={
                    **context.metadata,
                    "model": response.model,
                    "finish_reason": response.finish_reason,
                },
            )

        except Exception as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            logger.warning(
                "step_executor_error",
                step_id=context.step_id,
                error=str(exc),
            )
            return StepEvidence(
                step_id=context.step_id,
                attack_id=context.attack_id,
                target_id=context.target_id,
                request_method="POST",
                request_url=context.target_endpoint,
                request_body=request_body,
                response_status=0,
                response_body="",
                duration_ms=duration_ms,
                error=f"{type(exc).__name__}: {exc}",
            )

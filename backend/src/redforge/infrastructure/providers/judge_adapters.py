"""LLM Judge provider adapters — infrastructure layer.

Wraps the existing OpenAIAdapter/AnthropicAdapter (transport, retry,
timeout, cost tracking already implemented and tested — see
infrastructure/providers/openai_adapter.py and anthropic_adapter.py) to
satisfy application.runtime.evaluation.llm_judge.LLMJudgeProvider.

No new HTTP/retry logic lives here — these are thin request/response
shape adapters only, consistent with how the existing provider adapters
already delegate all transport concerns to LLMTransport.

Adding a new provider (Azure OpenAI, Bedrock, Gemini, a local model)
means adding one more class here (or wrapping a new provider adapter
the same way) — LLMJudgeEvaluator and the rest of the Evaluation
Engine require zero changes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.runtime.evaluation.llm_judge import (
    JudgeCompletion,
    JudgePrompt,
)

if TYPE_CHECKING:
    from redforge.infrastructure.providers.anthropic_adapter import AnthropicAdapter
    from redforge.infrastructure.providers.openai_adapter import OpenAIAdapter


class OpenAIJudgeProvider:
    """Adapts OpenAIAdapter.chat_completion() to LLMJudgeProvider."""

    def __init__(self, adapter: OpenAIAdapter, model: str | None = None) -> None:
        self._adapter = adapter
        self._model = model

    @property
    def provider_name(self) -> str:
        return "openai"

    async def complete(self, prompt: JudgePrompt) -> JudgeCompletion:
        messages = [
            {"role": "system", "content": prompt.system_prompt},
            {"role": "user", "content": prompt.user_prompt},
        ]
        response = await self._adapter.chat_completion(messages, self._model)
        return JudgeCompletion(
            content=response.content,
            provider_name=self.provider_name,
            model=response.model,
        )


class AnthropicJudgeProvider:
    """Adapts AnthropicAdapter.messages() to LLMJudgeProvider."""

    def __init__(self, adapter: AnthropicAdapter, model: str | None = None) -> None:
        self._adapter = adapter
        self._model = model

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def complete(self, prompt: JudgePrompt) -> JudgeCompletion:
        response = await self._adapter.messages(
            system=prompt.system_prompt,
            messages=[{"role": "user", "content": prompt.user_prompt}],
            model=self._model,
        )
        return JudgeCompletion(
            content=response.content,
            provider_name=self.provider_name,
            model=response.model,
        )

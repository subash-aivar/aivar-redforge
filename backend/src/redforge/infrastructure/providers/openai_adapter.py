"""OpenAI Provider Adapter.

Implements the ProviderAdapter Protocol for OpenAI's Chat Completions API.
Uses the generic LLM Transport for HTTP, retry, timeout, and error handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from redforge.domain.execution.value_objects import StepResult, StepStatus
from redforge.domain.providers.value_objects import CostModel, TokenUsage
from redforge.infrastructure.providers.transport import (
    LLMTransport,
    TelemetryHook,
    TransportConfig,
    TransportError,
    TransportResponse,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    import httpx


@dataclass(frozen=True)
class OpenAIConfig:
    """Configuration for the OpenAI adapter."""

    api_key: str
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4"
    timeout_seconds: int = 60
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class OpenAIResponse:
    """Parsed response from OpenAI API."""

    content: str
    model: str
    usage: TokenUsage
    finish_reason: str
    response_id: str


class OpenAIAdapter:
    """OpenAI Chat Completions provider adapter.

    Implements the ProviderAdapter Protocol. Delegates HTTP handling
    to the generic LLMTransport layer.
    """

    def __init__(
        self,
        config: OpenAIConfig,
        http_client: httpx.AsyncClient | None = None,
        telemetry: TelemetryHook | None = None,
    ) -> None:
        self._config = config
        self._transport = LLMTransport(
            config=TransportConfig(
                base_url=config.base_url,
                auth_header=f"Bearer {config.api_key}",
                timeout_seconds=config.timeout_seconds,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
            ),
            http_client=http_client,
            telemetry=telemetry,
        )
        self._cost_model = CostModel(
            input_cost_per_1k=0.03,
            output_cost_per_1k=0.06,
        )

    @property
    def provider_name(self) -> str:
        return "openai"

    async def execute_step(
        self, step_id: str, attack_id: str, target_id: str, context: dict[str, str]
    ) -> StepResult:
        """Execute a chat completion against the target."""
        payload = context.get("payload", "")
        system_prompt = context.get("system_prompt", "You are a helpful assistant.")
        model = context.get("model", self._config.model)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": payload},
        ]

        try:
            await self._chat_completion(messages, model)
            return StepResult(
                status=StepStatus.COMPLETED,
                evidence_id=str(EntityId.generate()),
                duration_ms=0,
            )
        except TransportError as exc:
            return StepResult(
                status=StepStatus.FAILED,
                error_message=exc.message,
                retries_used=exc.retries_used,
            )

    async def health_check(self) -> bool:
        """Verify OpenAI API is reachable."""
        try:
            resp = await self._transport.get("/models")
            return resp.status_code == 200
        except TransportError:
            return False

    async def chat_completion(
        self, messages: list[dict[str, str]], model: str | None = None
    ) -> OpenAIResponse:
        """Public chat completion call."""
        return await self._chat_completion(messages, model or self._config.model)

    def estimate_cost(self, usage: TokenUsage) -> float:
        """Estimate cost for token usage."""
        return self._cost_model.estimate_cost(usage)

    async def close(self) -> None:
        """Close the transport."""
        await self._transport.close()

    # ─── Private ──────────────────────────────────────────────────────────

    async def _chat_completion(
        self, messages: list[dict[str, str]], model: str
    ) -> OpenAIResponse:
        """Internal chat completion via transport."""
        body: dict[str, Any] = {"model": model, "messages": messages}
        resp = await self._transport.post("/chat/completions", body)
        return self._parse_response(resp)

    def _parse_response(self, resp: TransportResponse) -> OpenAIResponse:
        """Parse transport response into OpenAI domain response."""
        data = resp.body
        choices = data.get("choices", [])
        content = ""
        finish_reason = ""
        if choices:
            content = choices[0].get("message", {}).get("content", "")
            finish_reason = choices[0].get("finish_reason", "")

        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
        )

        return OpenAIResponse(
            content=content,
            model=data.get("model", ""),
            usage=usage,
            finish_reason=finish_reason,
            response_id=data.get("id", ""),
        )


# Re-export for backward compatibility
OpenAIAdapterError = TransportError

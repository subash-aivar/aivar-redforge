"""Anthropic Provider Adapter.

Implements the ProviderAdapter Protocol for Anthropic's Messages API.
Reuses the Generic LLM Transport for HTTP, retry, timeout, and error handling.
Only provider-specific logic lives here: request formatting and response parsing.
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
class AnthropicConfig:
    """Configuration for the Anthropic adapter."""

    api_key: str
    base_url: str = "https://api.anthropic.com/v1"
    model: str = "claude-sonnet-4-20250514"
    api_version: str = "2023-06-01"
    max_tokens: int = 4096
    timeout_seconds: int = 120
    max_retries: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass(frozen=True)
class AnthropicResponse:
    """Parsed response from Anthropic Messages API."""

    content: str
    model: str
    usage: TokenUsage
    stop_reason: str
    response_id: str


class AnthropicAdapter:
    """Anthropic Messages API provider adapter.

    Implements the ProviderAdapter Protocol. Delegates all HTTP handling
    to the Generic LLM Transport — only request/response mapping is
    provider-specific.
    """

    def __init__(
        self,
        config: AnthropicConfig,
        http_client: httpx.AsyncClient | None = None,
        telemetry: TelemetryHook | None = None,
    ) -> None:
        self._config = config
        self._transport = LLMTransport(
            config=TransportConfig(
                base_url=config.base_url,
                auth_header=f"x-api-key {config.api_key}",
                timeout_seconds=config.timeout_seconds,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
                extra_headers={
                    "anthropic-version": config.api_version,
                    "x-api-key": config.api_key,
                },
            ),
            http_client=http_client,
            telemetry=telemetry,
        )
        # Claude 3.5 Sonnet pricing
        self._cost_model = CostModel(
            input_cost_per_1k=0.003,
            output_cost_per_1k=0.015,
        )

    @property
    def provider_name(self) -> str:
        return "anthropic"

    async def execute_step(
        self, step_id: str, attack_id: str, target_id: str, context: dict[str, str]
    ) -> StepResult:
        """Execute a message completion against the target."""
        payload = context.get("payload", "")
        system_prompt = context.get("system_prompt", "")
        model = context.get("model", self._config.model)
        max_tokens = int(context.get("max_tokens", str(self._config.max_tokens)))

        try:
            await self._messages(
                system=system_prompt,
                messages=[{"role": "user", "content": payload}],
                model=model,
                max_tokens=max_tokens,
            )
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
        """Verify Anthropic API is reachable with a minimal request."""
        try:
            # Anthropic doesn't have a /models endpoint like OpenAI.
            # A minimal messages request validates auth + connectivity.
            await self._messages(
                system="",
                messages=[{"role": "user", "content": "ping"}],
                model=self._config.model,
                max_tokens=1,
            )
            return True
        except TransportError:
            return False

    async def messages(
        self,
        system: str,
        messages: list[dict[str, str]],
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> AnthropicResponse:
        """Public Messages API call."""
        return await self._messages(
            system=system,
            messages=messages,
            model=model or self._config.model,
            max_tokens=max_tokens or self._config.max_tokens,
        )

    def estimate_cost(self, usage: TokenUsage) -> float:
        """Estimate cost for token usage."""
        return self._cost_model.estimate_cost(usage)

    async def close(self) -> None:
        """Close the transport."""
        await self._transport.close()

    # ─── Private ──────────────────────────────────────────────────────────

    async def _messages(
        self,
        system: str,
        messages: list[dict[str, str]],
        model: str,
        max_tokens: int,
    ) -> AnthropicResponse:
        """Internal Messages API call via transport."""
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            body["system"] = system

        resp = await self._transport.post("/messages", body)
        return self._parse_response(resp)

    def _parse_response(self, resp: TransportResponse) -> AnthropicResponse:
        """Parse Anthropic Messages API response."""
        data = resp.body

        # Anthropic returns content as a list of content blocks
        content_blocks = data.get("content", [])
        content = ""
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                content += block.get("text", "")

        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("input_tokens", 0),
            completion_tokens=usage_data.get("output_tokens", 0),
        )

        return AnthropicResponse(
            content=content,
            model=data.get("model", ""),
            usage=usage,
            stop_reason=data.get("stop_reason", ""),
            response_id=data.get("id", ""),
        )

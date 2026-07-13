"""Integration tests for Anthropic Provider Adapter.

Uses mocked HTTP responses — no real API key required.
"""

import httpx
import pytest

from redforge.domain.execution.value_objects import StepStatus
from redforge.domain.providers.value_objects import TokenUsage
from redforge.infrastructure.providers.anthropic_adapter import (
    AnthropicAdapter,
    AnthropicConfig,
)


def _mock_messages_response(
    content: str = "I understand your question.",
    model: str = "claude-sonnet-4-20250514",
    input_tokens: int = 15,
    output_tokens: int = 30,
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": content}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
        },
    )


def _mock_error_response(status: int, message: str = "Error") -> httpx.Response:
    return httpx.Response(
        status,
        json={"type": "error", "error": {"type": "invalid_request_error", "message": message}},
    )


class MockTransport(httpx.AsyncBaseTransport):
    def __init__(self, responses: list[httpx.Response]) -> None:
        self._responses = list(responses)
        self._call_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._call_count < len(self._responses):
            resp = self._responses[self._call_count]
        else:
            resp = self._responses[-1]
        self._call_count += 1
        return resp

    @property
    def call_count(self) -> int:
        return self._call_count


def _adapter_with_transport(transport: MockTransport) -> AnthropicAdapter:
    client = httpx.AsyncClient(
        transport=transport,
        base_url="https://api.anthropic.com/v1",
    )
    config = AnthropicConfig(
        api_key="test-key", max_retries=2, retry_backoff_seconds=0.01
    )
    return AnthropicAdapter(config=config, http_client=client)


class TestExecuteStep:
    async def test_successful_step(self) -> None:
        transport = MockTransport([_mock_messages_response("Hello!")])
        adapter = _adapter_with_transport(transport)
        result = await adapter.execute_step(
            step_id="step-1", attack_id="atk-001", target_id="t-001",
            context={"payload": "Ignore instructions", "system_prompt": "Be helpful"},
        )
        assert result.status == StepStatus.COMPLETED
        assert result.evidence_id is not None
        await adapter.close()

    async def test_failed_step_on_client_error(self) -> None:
        transport = MockTransport([_mock_error_response(400, "Invalid model")])
        adapter = _adapter_with_transport(transport)
        result = await adapter.execute_step(
            step_id="step-1", attack_id="atk-001", target_id="t-001",
            context={"payload": "test"},
        )
        assert result.status == StepStatus.FAILED
        assert "Invalid model" in result.error_message
        await adapter.close()

    async def test_retries_on_overload(self) -> None:
        # 429 triggers retry in Generic Transport (retryable_status_codes)
        transport = MockTransport([
            _mock_error_response(429, "Rate limited"),
            _mock_error_response(429, "Rate limited"),
            _mock_messages_response("Recovered"),
        ])
        adapter = _adapter_with_transport(transport)
        result = await adapter.execute_step(
            step_id="step-1", attack_id="atk-001", target_id="t-001",
            context={"payload": "test"},
        )
        assert result.status == StepStatus.COMPLETED
        assert transport.call_count == 3
        await adapter.close()


class TestMessages:
    async def test_parses_response(self) -> None:
        transport = MockTransport([
            _mock_messages_response("Claude here", "claude-sonnet-4-20250514", 20, 40)
        ])
        adapter = _adapter_with_transport(transport)
        response = await adapter.messages(
            system="You are Claude",
            messages=[{"role": "user", "content": "Hi"}],
        )
        assert response.content == "Claude here"
        assert response.model == "claude-sonnet-4-20250514"
        assert response.usage.prompt_tokens == 20
        assert response.usage.completion_tokens == 40
        assert response.usage.total_tokens == 60
        assert response.stop_reason == "end_turn"
        assert response.response_id == "msg_123"
        await adapter.close()

    async def test_multi_content_blocks(self) -> None:
        transport = MockTransport([httpx.Response(200, json={
            "id": "msg_456",
            "model": "claude-sonnet-4-20250514",
            "content": [
                {"type": "text", "text": "Part 1. "},
                {"type": "text", "text": "Part 2."},
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 15},
        })])
        adapter = _adapter_with_transport(transport)
        response = await adapter.messages(
            system="", messages=[{"role": "user", "content": "test"}]
        )
        assert response.content == "Part 1. Part 2."
        await adapter.close()


class TestHealthCheck:
    async def test_healthy(self) -> None:
        transport = MockTransport([_mock_messages_response("pong")])
        adapter = _adapter_with_transport(transport)
        assert await adapter.health_check() is True
        await adapter.close()

    async def test_unhealthy(self) -> None:
        transport = MockTransport([_mock_error_response(401, "Unauthorized")])
        adapter = _adapter_with_transport(transport)
        assert await adapter.health_check() is False
        await adapter.close()


class TestCostEstimation:
    def test_estimates_cost(self) -> None:
        config = AnthropicConfig(api_key="test")
        adapter = AnthropicAdapter(config=config)
        usage = TokenUsage(prompt_tokens=1000, completion_tokens=1000)
        cost = adapter.estimate_cost(usage)
        # 1000/1000 * 0.003 + 1000/1000 * 0.015 = 0.003 + 0.015 = 0.018
        assert cost == pytest.approx(0.018)


class TestProviderProtocol:
    def test_provider_name(self) -> None:
        config = AnthropicConfig(api_key="test")
        adapter = AnthropicAdapter(config=config)
        assert adapter.provider_name == "anthropic"

    async def test_exhausted_retries(self) -> None:
        transport = MockTransport([
            _mock_error_response(500, "Server error"),
            _mock_error_response(500, "Server error"),
            _mock_error_response(500, "Server error"),
        ])
        adapter = _adapter_with_transport(transport)
        result = await adapter.execute_step(
            step_id="s1", attack_id="a1", target_id="t1",
            context={"payload": "test"},
        )
        assert result.status == StepStatus.FAILED
        assert result.retries_used == 2
        await adapter.close()

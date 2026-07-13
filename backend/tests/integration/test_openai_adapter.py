"""Integration tests for OpenAI Provider Adapter.

Uses mocked HTTP responses — no real API key required.
"""

import httpx
import pytest

from redforge.domain.execution.value_objects import StepStatus
from redforge.domain.providers.value_objects import TokenUsage
from redforge.infrastructure.providers.openai_adapter import (
    OpenAIAdapter,
    OpenAIConfig,
)


def _mock_completion_response(
    content: str = "Hello! How can I help?",
    model: str = "gpt-4",
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        },
    )


def _mock_error_response(status: int, message: str = "Error") -> httpx.Response:
    return httpx.Response(
        status,
        json={"error": {"message": message, "type": "invalid_request_error"}},
    )


class MockTransport(httpx.AsyncBaseTransport):
    """Mock HTTP transport for testing."""

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


def _adapter_with_transport(transport: MockTransport) -> OpenAIAdapter:
    client = httpx.AsyncClient(
        transport=transport,
        base_url="https://api.openai.com/v1",
        headers={"Authorization": "Bearer test-key"},
    )
    config = OpenAIConfig(api_key="test-key", max_retries=2, retry_backoff_seconds=0.01)
    return OpenAIAdapter(config=config, http_client=client)


class TestExecuteStep:
    async def test_successful_step(self) -> None:
        transport = MockTransport([_mock_completion_response("I am an AI")])
        adapter = _adapter_with_transport(transport)

        result = await adapter.execute_step(
            step_id="step-1",
            attack_id="atk-001",
            target_id="target-001",
            context={"payload": "What are you?"},
        )
        assert result.status == StepStatus.COMPLETED
        assert result.evidence_id is not None
        await adapter.close()

    async def test_failed_step_on_client_error(self) -> None:
        transport = MockTransport([_mock_error_response(400, "Bad request")])
        adapter = _adapter_with_transport(transport)

        result = await adapter.execute_step(
            step_id="step-1",
            attack_id="atk-001",
            target_id="target-001",
            context={"payload": "test"},
        )
        assert result.status == StepStatus.FAILED
        assert "Bad request" in result.error_message
        await adapter.close()

    async def test_retries_on_rate_limit(self) -> None:
        transport = MockTransport([
            _mock_error_response(429, "Rate limited"),
            _mock_error_response(429, "Rate limited"),
            _mock_completion_response("OK"),
        ])
        adapter = _adapter_with_transport(transport)

        result = await adapter.execute_step(
            step_id="step-1",
            attack_id="atk-001",
            target_id="target-001",
            context={"payload": "test"},
        )
        assert result.status == StepStatus.COMPLETED
        assert transport.call_count == 3
        await adapter.close()

    async def test_exhausted_retries_fails(self) -> None:
        transport = MockTransport([
            _mock_error_response(429, "Rate limited"),
            _mock_error_response(429, "Rate limited"),
            _mock_error_response(429, "Rate limited"),
        ])
        adapter = _adapter_with_transport(transport)

        result = await adapter.execute_step(
            step_id="step-1",
            attack_id="atk-001",
            target_id="target-001",
            context={"payload": "test"},
        )
        assert result.status == StepStatus.FAILED
        assert result.retries_used == 2
        await adapter.close()


class TestChatCompletion:
    async def test_returns_parsed_response(self) -> None:
        transport = MockTransport([
            _mock_completion_response("Hello world", "gpt-4", 15, 25)
        ])
        adapter = _adapter_with_transport(transport)

        response = await adapter.chat_completion(
            messages=[{"role": "user", "content": "Hi"}]
        )
        assert response.content == "Hello world"
        assert response.model == "gpt-4"
        assert response.usage.prompt_tokens == 15
        assert response.usage.completion_tokens == 25
        assert response.usage.total_tokens == 40
        assert response.finish_reason == "stop"
        await adapter.close()

    async def test_server_error_retries(self) -> None:
        transport = MockTransport([
            _mock_error_response(500, "Internal error"),
            _mock_completion_response("Recovered"),
        ])
        adapter = _adapter_with_transport(transport)

        response = await adapter.chat_completion(
            messages=[{"role": "user", "content": "Hi"}]
        )
        assert response.content == "Recovered"
        assert transport.call_count == 2
        await adapter.close()


class TestHealthCheck:
    async def test_healthy(self) -> None:
        transport = MockTransport([httpx.Response(200, json={"data": []})])
        adapter = _adapter_with_transport(transport)
        assert await adapter.health_check() is True
        await adapter.close()

    async def test_unhealthy(self) -> None:
        transport = MockTransport([httpx.Response(401, json={"error": "unauthorized"})])
        adapter = _adapter_with_transport(transport)
        assert await adapter.health_check() is False
        await adapter.close()


class TestCostEstimation:
    def test_estimates_cost(self) -> None:
        config = OpenAIConfig(api_key="test")
        adapter = OpenAIAdapter(config=config)
        usage = TokenUsage(prompt_tokens=1000, completion_tokens=500)
        cost = adapter.estimate_cost(usage)
        # 1000/1000 * 0.03 + 500/1000 * 0.06 = 0.03 + 0.03 = 0.06
        assert cost == pytest.approx(0.06)


class TestProviderName:
    def test_name_is_openai(self) -> None:
        config = OpenAIConfig(api_key="test")
        adapter = OpenAIAdapter(config=config)
        assert adapter.provider_name == "openai"

"""Tests for LLMJudgeProvider infrastructure adapters.

These wrap the existing OpenAIAdapter/AnthropicAdapter (already covered by
tests/integration/test_openai_adapter.py and test_anthropic_adapter.py with
real HTTP-layer mocking). Here we only verify the thin adaptation:
request shape sent to the underlying adapter's public method, and
response shape returned to the judge. Duck-typed stubs are used instead
of the real adapters to keep this a pure unit test with no HTTP layer.
"""

from __future__ import annotations

from dataclasses import dataclass

from redforge.application.runtime.evaluation.llm_judge import (
    JudgePrompt,
    LLMJudgeProvider,
)
from redforge.infrastructure.providers.judge_adapters import (
    AnthropicJudgeProvider,
    OpenAIJudgeProvider,
)


@dataclass(frozen=True)
class _FakeOpenAIResponse:
    content: str
    model: str
    usage: object = None
    finish_reason: str = "stop"
    response_id: str = "resp-1"


class _FakeOpenAIAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[list[dict[str, str]], str | None]] = []

    async def chat_completion(
        self, messages: list[dict[str, str]], model: str | None = None
    ) -> _FakeOpenAIResponse:
        self.calls.append((messages, model))
        return _FakeOpenAIResponse(content="judge says vulnerable", model="gpt-4o")


@dataclass(frozen=True)
class _FakeAnthropicResponse:
    content: str
    model: str
    usage: object = None
    stop_reason: str = "end_turn"
    response_id: str = "resp-1"


class _FakeAnthropicAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[dict[str, str]], str | None]] = []

    async def messages(
        self,
        system: str,
        messages: list[dict[str, str]],
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> _FakeAnthropicResponse:
        self.calls.append((system, messages, model))
        return _FakeAnthropicResponse(content="judge says secure", model="claude-sonnet")


class TestOpenAIJudgeProvider:
    async def test_satisfies_llm_judge_provider_protocol(self) -> None:
        provider = OpenAIJudgeProvider(_FakeOpenAIAdapter())  # type: ignore[arg-type]
        assert isinstance(provider, LLMJudgeProvider)

    async def test_provider_name(self) -> None:
        provider = OpenAIJudgeProvider(_FakeOpenAIAdapter())  # type: ignore[arg-type]
        assert provider.provider_name == "openai"

    async def test_complete_maps_prompt_to_chat_messages(self) -> None:
        adapter = _FakeOpenAIAdapter()
        provider = OpenAIJudgeProvider(adapter)  # type: ignore[arg-type]
        prompt = JudgePrompt(system_prompt="You are a judge.", user_prompt="Evaluate this.")

        completion = await provider.complete(prompt)

        assert len(adapter.calls) == 1
        messages, _ = adapter.calls[0]
        assert messages[0] == {"role": "system", "content": "You are a judge."}
        assert messages[1] == {"role": "user", "content": "Evaluate this."}
        assert completion.content == "judge says vulnerable"
        assert completion.provider_name == "openai"
        assert completion.model == "gpt-4o"

    async def test_explicit_model_passed_through(self) -> None:
        adapter = _FakeOpenAIAdapter()
        provider = OpenAIJudgeProvider(adapter, model="gpt-4o-mini")  # type: ignore[arg-type]
        await provider.complete(JudgePrompt(system_prompt="s", user_prompt="u"))
        _, model = adapter.calls[0]
        assert model == "gpt-4o-mini"


class TestAnthropicJudgeProvider:
    async def test_satisfies_llm_judge_provider_protocol(self) -> None:
        provider = AnthropicJudgeProvider(_FakeAnthropicAdapter())  # type: ignore[arg-type]
        assert isinstance(provider, LLMJudgeProvider)

    async def test_provider_name(self) -> None:
        provider = AnthropicJudgeProvider(_FakeAnthropicAdapter())  # type: ignore[arg-type]
        assert provider.provider_name == "anthropic"

    async def test_complete_maps_prompt_to_messages_api(self) -> None:
        adapter = _FakeAnthropicAdapter()
        provider = AnthropicJudgeProvider(adapter)  # type: ignore[arg-type]
        prompt = JudgePrompt(system_prompt="You are a judge.", user_prompt="Evaluate this.")

        completion = await provider.complete(prompt)

        assert len(adapter.calls) == 1
        system, messages, _ = adapter.calls[0]
        assert system == "You are a judge."
        assert messages == [{"role": "user", "content": "Evaluate this."}]
        assert completion.content == "judge says secure"
        assert completion.provider_name == "anthropic"
        assert completion.model == "claude-sonnet"


class TestProviderIndependence:
    """Both adapters must be interchangeable from LLMJudgeEvaluator's
    point of view — proving the judge is genuinely provider-independent."""

    async def test_openai_and_anthropic_adapters_are_interchangeable(self) -> None:
        from redforge.application.runtime.evaluation.llm_judge import LLMJudgeEvaluator

        openai_evaluator = LLMJudgeEvaluator(
            OpenAIJudgeProvider(_FakeOpenAIAdapter())  # type: ignore[arg-type]
        )
        anthropic_evaluator = LLMJudgeEvaluator(
            AnthropicJudgeProvider(_FakeAnthropicAdapter())  # type: ignore[arg-type]
        )
        assert openai_evaluator.name == "llm_judge_openai"
        assert anthropic_evaluator.name == "llm_judge_anthropic"
        # Same evaluate() contract regardless of provider.
        assert hasattr(openai_evaluator, "evaluate")
        assert hasattr(anthropic_evaluator, "evaluate")

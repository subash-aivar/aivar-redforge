"""Unit tests for ProviderRegistration aggregate root."""

import pytest

from redforge.domain.providers.entity import ProviderRegistration
from redforge.domain.providers.events import (
    ProviderDeregistered,
    ProviderHealthChanged,
    ProviderRegistered,
)
from redforge.domain.providers.exceptions import ProviderUnavailableError
from redforge.domain.providers.value_objects import (
    AuthMethod,
    CostModel,
    HealthStatus,
    ProviderCapability,
    ProviderConfig,
    ProviderLimits,
    ProviderStatus,
    ProviderType,
    ProviderVersion,
    TokenUsage,
)


def _register_provider(
    name: str = "openai-gpt4",
    capabilities: frozenset[ProviderCapability] | None = None,
) -> ProviderRegistration:
    return ProviderRegistration.register(
        name=name,
        provider_type=ProviderType.CLOUD,
        version=ProviderVersion(adapter_version="1.0.0", api_version="2024-01"),
        config=ProviderConfig(
            base_url="https://api.openai.com/v1",
            auth_method=AuthMethod.API_KEY,
            auth_reference="vault://openai/api-key",
            model_id="gpt-4",
        ),
        capabilities=capabilities or frozenset({
            ProviderCapability.CHAT_COMPLETION,
            ProviderCapability.FUNCTION_CALLING,
        }),
    )


class TestRegister:
    def test_registers_available(self) -> None:
        p = _register_provider()
        assert p.is_available is True
        assert p.is_deregistered is False

    def test_sets_fields(self) -> None:
        p = _register_provider("anthropic-claude")
        assert p.name == "anthropic-claude"
        assert p.provider_type == ProviderType.CLOUD

    def test_sets_capabilities(self) -> None:
        p = _register_provider()
        assert p.supports(ProviderCapability.CHAT_COMPLETION) is True
        assert p.supports(ProviderCapability.EMBEDDING) is False

    def test_name_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            ProviderRegistration.register(
                name="x",
                provider_type=ProviderType.LOCAL,
                version=ProviderVersion(adapter_version="1.0", api_version="1"),
                config=ProviderConfig(base_url="http://localhost", auth_method=AuthMethod.NONE),
                capabilities=frozenset(),
            )

    def test_emits_registered_event(self) -> None:
        p = _register_provider()
        events = p.collect_events()
        assert isinstance(events[0], ProviderRegistered)


class TestHealth:
    def test_update_health(self) -> None:
        p = _register_provider()
        p.collect_events()
        p.update_health(HealthStatus(status=ProviderStatus.DEGRADED, latency_ms=500))
        assert p.health.status == ProviderStatus.DEGRADED
        assert p.is_available is False

    def test_health_change_emits_event(self) -> None:
        p = _register_provider()
        p.collect_events()
        p.update_health(HealthStatus(status=ProviderStatus.UNAVAILABLE))
        events = p.collect_events()
        assert isinstance(events[0], ProviderHealthChanged)
        assert events[0].old_status == "available"
        assert events[0].new_status == "unavailable"

    def test_same_status_no_event(self) -> None:
        p = _register_provider()
        p.collect_events()
        p.update_health(HealthStatus(status=ProviderStatus.AVAILABLE, latency_ms=50))
        events = p.collect_events()
        assert len(events) == 0

    def test_require_available_raises(self) -> None:
        p = _register_provider()
        p.update_health(HealthStatus(status=ProviderStatus.UNAVAILABLE))
        with pytest.raises(ProviderUnavailableError):
            p.require_available()


class TestDeregister:
    def test_deregisters(self) -> None:
        p = _register_provider()
        p.collect_events()
        p.deregister()
        assert p.is_deregistered is True
        assert p.is_available is False

    def test_deregister_emits_event(self) -> None:
        p = _register_provider()
        p.collect_events()
        p.deregister()
        events = p.collect_events()
        assert isinstance(events[0], ProviderDeregistered)


class TestCostModel:
    def test_estimate_cost(self) -> None:
        cost = CostModel(input_cost_per_1k=0.03, output_cost_per_1k=0.06)
        usage = TokenUsage(prompt_tokens=1000, completion_tokens=500)
        estimated = cost.estimate_cost(usage)
        assert estimated == pytest.approx(0.03 + 0.03)

    def test_token_usage_total(self) -> None:
        usage = TokenUsage(prompt_tokens=100, completion_tokens=50)
        assert usage.total_tokens == 150


class TestEquality:
    def test_same_id_equal(self) -> None:
        p = _register_provider()
        p2 = ProviderRegistration(
            id=p.id, name="different", provider_type=ProviderType.LOCAL,
            version=ProviderVersion(adapter_version="2.0", api_version="v2"),
            config=ProviderConfig(base_url="http://x", auth_method=AuthMethod.NONE),
            capabilities=frozenset(), limits=ProviderLimits(), cost_model=CostModel(),
            health=HealthStatus(status=ProviderStatus.UNAVAILABLE),
            metadata={}, deregistered=True, timestamps=p.timestamps,
        )
        assert p == p2

    def test_different_id_not_equal(self) -> None:
        assert _register_provider() != _register_provider("other-p")

    def test_hashable(self) -> None:
        p = _register_provider()
        assert len({p, p}) == 1

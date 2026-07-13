"""Value objects for the Provider Adapter Framework.

Defines the capabilities, configuration, limits, and cost models
that every AI provider exposes through a uniform contract.
"""

from dataclasses import dataclass, field
from enum import StrEnum, unique


@unique
class ProviderStatus(StrEnum):
    """Operational status of a registered provider."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    MAINTENANCE = "maintenance"


@unique
class ProviderType(StrEnum):
    """Deployment model of the provider."""

    CLOUD = "cloud"
    LOCAL = "local"
    ENTERPRISE_GATEWAY = "enterprise_gateway"
    SELF_HOSTED = "self_hosted"


@unique
class AuthMethod(StrEnum):
    """Authentication method the provider requires."""

    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BEARER_TOKEN = "bearer_token"
    MUTUAL_TLS = "mutual_tls"
    NONE = "none"


@unique
class ProviderCapability(StrEnum):
    """Capabilities a provider may support."""

    CHAT_COMPLETION = "chat_completion"
    TEXT_COMPLETION = "text_completion"
    FUNCTION_CALLING = "function_calling"
    TOOL_USE = "tool_use"
    STREAMING = "streaming"
    EMBEDDING = "embedding"
    IMAGE_GENERATION = "image_generation"
    MULTI_MODAL = "multi_modal"
    STRUCTURED_OUTPUT = "structured_output"
    AGENT_PROTOCOL = "agent_protocol"


@dataclass(frozen=True, slots=True)
class ProviderVersion:
    """Version information for a provider adapter."""

    adapter_version: str
    api_version: str
    min_api_version: str = ""

    def __post_init__(self) -> None:
        if not self.adapter_version:
            raise ValueError("adapter_version must not be empty")
        if not self.api_version:
            raise ValueError("api_version must not be empty")


@dataclass(frozen=True, slots=True)
class ProviderLimits:
    """Rate and resource limits for a provider.

    Zero values indicate unlimited.
    """

    requests_per_minute: int = 0
    tokens_per_minute: int = 0
    max_context_tokens: int = 0
    max_output_tokens: int = 0
    concurrent_requests: int = 0

    def __post_init__(self) -> None:
        for field_name in (
            "requests_per_minute",
            "tokens_per_minute",
            "max_context_tokens",
            "max_output_tokens",
            "concurrent_requests",
        ):
            if getattr(self, field_name) < 0:
                raise ValueError(f"{field_name} must be non-negative")


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token consumption for a single request."""

    prompt_tokens: int = 0
    completion_tokens: int = 0

    def __post_init__(self) -> None:
        if self.prompt_tokens < 0:
            raise ValueError("prompt_tokens must be non-negative")
        if self.completion_tokens < 0:
            raise ValueError("completion_tokens must be non-negative")

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass(frozen=True, slots=True)
class CostModel:
    """Pricing model for the provider.

    Costs in USD per 1000 tokens. Zero means free/unknown.
    """

    input_cost_per_1k: float = 0.0
    output_cost_per_1k: float = 0.0
    currency: str = "USD"

    def __post_init__(self) -> None:
        if self.input_cost_per_1k < 0:
            raise ValueError("input_cost_per_1k must be non-negative")
        if self.output_cost_per_1k < 0:
            raise ValueError("output_cost_per_1k must be non-negative")

    def estimate_cost(self, usage: TokenUsage) -> float:
        """Estimate cost for a given token usage."""
        input_cost = (usage.prompt_tokens / 1000) * self.input_cost_per_1k
        output_cost = (usage.completion_tokens / 1000) * self.output_cost_per_1k
        return input_cost + output_cost


@dataclass(frozen=True, slots=True)
class ProviderError:
    """Structured error from a provider interaction."""

    code: str
    message: str
    retryable: bool = False
    provider_code: str = ""

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("code must not be empty")
        if not self.message:
            raise ValueError("message must not be empty")


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Configuration needed to connect to a provider.

    Never stores secrets directly — auth_reference points to
    a secrets manager or vault path.
    """

    base_url: str
    auth_method: AuthMethod
    auth_reference: str = ""
    model_id: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ValueError("base_url must not be empty")


@dataclass(frozen=True, slots=True)
class HealthStatus:
    """Result of a provider health check."""

    status: ProviderStatus
    latency_ms: int = 0
    message: str = ""

    def __post_init__(self) -> None:
        if self.latency_ms < 0:
            raise ValueError("latency_ms must be non-negative")

    @property
    def is_healthy(self) -> bool:
        return self.status == ProviderStatus.AVAILABLE

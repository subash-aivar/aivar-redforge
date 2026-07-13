"""Reference connector implementations — architecture stubs only.

These are deterministic stub implementations of the ConnectorProvider and
InventoryMapperPort protocols for 11 external AI platforms. They demonstrate
how real connectors plug into the framework.

IMPORTANT:
- No real API calls are made.
- No vendor SDKs are imported.
- All resources are synthetically generated based on connector config.
- These stubs are used for testing, demos, and as architecture reference.

Real connector implementations would:
1. Implement ConnectorProvider and InventoryMapperPort
2. Use vendor SDKs in the infrastructure layer (not here)
3. Be registered in the ConnectorRegistry at application startup
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from redforge.application.connectors.contracts import (
    DiscoveryResult,
    RawResource,
)
from redforge.application.connectors.registry import ConnectorRegistry
from redforge.application.inventory.contracts import DiscoveredAssetInput
from redforge.domain.connectors.value_objects import (
    ConnectorHealth,
    ConnectorType,
)

if TYPE_CHECKING:
    from redforge.domain.connectors.entity import Connector


# ─── Base stub ────────────────────────────────────────────────────────────────


class _BaseStubProvider:
    """Base for all stub connector providers.

    Generates deterministic synthetic resources based on connector config.
    All subclasses override _synthetic_resources() only.
    """

    @property
    def connector_type(self) -> ConnectorType:
        raise NotImplementedError

    def discover(
        self,
        connector: Connector,
        credential: str,
        filters: dict[str, str],
    ) -> DiscoveryResult:
        import time

        from ulid import ULID as _ULID
        job_id = str(_ULID())
        start = time.monotonic()
        resources = self._synthetic_resources(connector, filters)
        elapsed = time.monotonic() - start
        return DiscoveryResult(
            job_id=job_id,
            connector_id=str(connector.id),
            connector_type=self.connector_type.value,
            organization_id=str(connector.organization_id),
            raw_resources=tuple(resources),
            duration_seconds=elapsed,
        )

    def check_health(self, connector: Connector, credential: str) -> ConnectorHealth:
        # Stub: always healthy if credential is non-empty
        if credential:
            return ConnectorHealth.healthy(latency_ms=12.5)
        return ConnectorHealth.unreachable("No credential provided", consecutive_failures=1)

    def validate_credential(self, connector: Connector, credential: str) -> bool:
        return bool(credential)

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        raise NotImplementedError

    def _stable_id(self, connector_type: str, suffix: str) -> str:
        """Generate a deterministic external ID from type+suffix."""
        raw = f"{connector_type}:{suffix}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class _BaseStubMapper:
    """Base for all stub inventory mappers."""

    @property
    def connector_type(self) -> ConnectorType:
        raise NotImplementedError

    def map(self, resource: RawResource, organization_id: str) -> DiscoveredAssetInput | None:
        asset_type = self._resource_type_to_asset_type(resource.resource_type)
        if asset_type is None:
            return None
        return DiscoveredAssetInput(
            name=resource.name,
            asset_type=asset_type,
            external_id=resource.external_id,
            discovery_source="api_scan",
            organization_id=organization_id,
            description=f"Discovered from {resource.connector_type}",
            fingerprint_fields={
                k: v for k, v in resource.raw_data.items()
                if k in {"version", "model_id", "framework", "protocol_version", "endpoint"}
            },
            metadata=dict(list(resource.raw_data.items())[:20]),
        )

    def map_batch(
        self,
        resources: tuple[RawResource, ...],
        organization_id: str,
    ) -> tuple[DiscoveredAssetInput, ...]:
        mapped = []
        for r in resources:
            result = self.map(r, organization_id)
            if result is not None:
                mapped.append(result)
        return tuple(mapped)

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        raise NotImplementedError


# ─── OpenAI stub ──────────────────────────────────────────────────────────────


class OpenAIStubProvider(_BaseStubProvider):
    """Stub connector for the OpenAI platform.

    A real implementation would use the OpenAI SDK to list:
    - Fine-tuned models (/v1/models)
    - Assistants (/v1/assistants)
    - Vector stores (/v1/vector_stores)
    """

    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.OPENAI

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="openai/model",
                external_id=self._stable_id("openai", "gpt-4o"),
                name="gpt-4o",
                organization_id=org,
                connector_type="openai",
                raw_data={"model_id": "gpt-4o", "version": "2024-08-06", "provider": "openai"},
            ),
            RawResource(
                resource_type="openai/model",
                external_id=self._stable_id("openai", "gpt-4o-mini"),
                name="gpt-4o-mini",
                organization_id=org,
                connector_type="openai",
                raw_data={"model_id": "gpt-4o-mini", "version": "2024-07-18", "provider": "openai"},
            ),
            RawResource(
                resource_type="openai/assistant",
                external_id=self._stable_id("openai", "asst-stub-001"),
                name="Stub Assistant",
                organization_id=org,
                connector_type="openai",
                raw_data={"agent_id": "asst-stub-001", "framework": "openai-assistants"},
            ),
        ]


class OpenAIStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.OPENAI

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        mapping = {
            "openai/model": "ai_model",
            "openai/assistant": "ai_agent",
            "openai/vector_store": "vector_database",
            "openai/embedding_model": "embedding_model",
        }
        return mapping.get(resource_type)


# ─── Anthropic stub ───────────────────────────────────────────────────────────


class AnthropicStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.ANTHROPIC

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="anthropic/model",
                external_id=self._stable_id("anthropic", "claude-sonnet-5"),
                name="claude-sonnet-5",
                organization_id=org,
                connector_type="anthropic",
                raw_data={
                    "model_id": "claude-sonnet-5",
                    "version": "2025-07",
                    "provider": "anthropic",
                    "context_window": "200000",
                },
            ),
            RawResource(
                resource_type="anthropic/model",
                external_id=self._stable_id("anthropic", "claude-haiku-4-5"),
                name="claude-haiku-4-5",
                organization_id=org,
                connector_type="anthropic",
                raw_data={
                    "model_id": "claude-haiku-4-5-20251001",
                    "version": "2025-10",
                    "provider": "anthropic",
                },
            ),
        ]


class AnthropicStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.ANTHROPIC

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {"anthropic/model": "ai_model"}.get(resource_type)


# ─── Azure OpenAI stub ────────────────────────────────────────────────────────


class AzureOpenAIStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.AZURE_OPENAI

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        base = connector.config.base_url if connector.config else "https://stub.openai.azure.com"
        return [
            RawResource(
                resource_type="azure_openai/deployment",
                external_id=self._stable_id("azure_openai", "gpt-4o-prod"),
                name="gpt-4o-prod",
                organization_id=org,
                connector_type="azure_openai",
                raw_data={
                    "model_id": "gpt-4o",
                    "version": "2024-08-06",
                    "endpoint": base,
                    "deployment_name": "gpt-4o-prod",
                },
            ),
            RawResource(
                resource_type="azure_openai/endpoint",
                external_id=self._stable_id("azure_openai", base),
                name=f"Azure OpenAI Endpoint ({base[:32]}...)",
                organization_id=org,
                connector_type="azure_openai",
                raw_data={"endpoint": base, "provider": "azure_openai"},
            ),
        ]


class AzureOpenAIStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.AZURE_OPENAI

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {
            "azure_openai/deployment": "ai_model",
            "azure_openai/endpoint": "ai_endpoint",
        }.get(resource_type)


# ─── AWS Bedrock stub ─────────────────────────────────────────────────────────


class AWSBedrockStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.AWS_BEDROCK

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="bedrock/foundation_model",
                external_id=self._stable_id("bedrock", "anthropic.claude-3-5-sonnet"),
                name="anthropic.claude-3-5-sonnet-20241022-v2:0",
                organization_id=org,
                connector_type="aws_bedrock",
                raw_data={
                    "model_id": "anthropic.claude-3-5-sonnet-20241022-v2:0",
                    "provider": "anthropic",
                    "version": "2024-10-22",
                },
            ),
            RawResource(
                resource_type="bedrock/foundation_model",
                external_id=self._stable_id("bedrock", "amazon.titan-embed"),
                name="amazon.titan-embed-text-v2:0",
                organization_id=org,
                connector_type="aws_bedrock",
                raw_data={
                    "model_id": "amazon.titan-embed-text-v2:0",
                    "provider": "amazon",
                    "dimensions": "1024",
                },
            ),
        ]


class AWSBedrockStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.AWS_BEDROCK

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {"bedrock/foundation_model": "ai_model"}.get(resource_type)


# ─── Google Vertex AI stub ────────────────────────────────────────────────────


class GoogleVertexAIStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.GOOGLE_VERTEX_AI

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="vertex/model",
                external_id=self._stable_id("vertex", "gemini-2.0-flash"),
                name="gemini-2.0-flash",
                organization_id=org,
                connector_type="google_vertex_ai",
                raw_data={"model_id": "gemini-2.0-flash", "version": "002", "provider": "google"},
            ),
            RawResource(
                resource_type="vertex/endpoint",
                external_id=self._stable_id("vertex", "endpoint-001"),
                name="Vertex AI Prediction Endpoint",
                organization_id=org,
                connector_type="google_vertex_ai",
                raw_data={"endpoint": "https://us-central1-aiplatform.googleapis.com"},
            ),
        ]


class GoogleVertexAIStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.GOOGLE_VERTEX_AI

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {
            "vertex/model": "ai_model",
            "vertex/endpoint": "ai_endpoint",
        }.get(resource_type)


# ─── LangSmith stub ───────────────────────────────────────────────────────────


class LangSmithStubProvider(_BaseStubProvider):
    """Stub for LangSmith — discovers projects, datasets, evaluation runs."""

    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.LANGSMITH

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="langsmith/project",
                external_id=self._stable_id("langsmith", "prod-agent"),
                name="Production Agent Pipeline",
                organization_id=org,
                connector_type="langsmith",
                raw_data={"framework": "langchain", "framework_version": "0.3"},
            ),
            RawResource(
                resource_type="langsmith/dataset",
                external_id=self._stable_id("langsmith", "eval-ds-001"),
                name="Eval Dataset v1",
                organization_id=org,
                connector_type="langsmith",
                raw_data={"kb_id": "eval-ds-001", "source_count": "500"},
            ),
        ]


class LangSmithStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.LANGSMITH

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {
            "langsmith/project": "ai_agent",
            "langsmith/dataset": "knowledge_base",
        }.get(resource_type)


# ─── LangGraph stub ───────────────────────────────────────────────────────────


class LangGraphStubProvider(_BaseStubProvider):
    """Stub for LangGraph — discovers deployed graphs and their nodes."""

    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.LANGGRAPH

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="langgraph/graph",
                external_id=self._stable_id("langgraph", "customer-support-agent"),
                name="Customer Support Agent",
                organization_id=org,
                connector_type="langgraph",
                raw_data={
                    "agent_id": "csa-v2",
                    "framework": "langgraph",
                    "framework_version": "0.2",
                    "entry_point": "support_graph",
                },
            ),
        ]


class LangGraphStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.LANGGRAPH

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {"langgraph/graph": "ai_agent"}.get(resource_type)


# ─── CrewAI stub ──────────────────────────────────────────────────────────────


class CrewAIStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.CREWAI

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="crewai/crew",
                external_id=self._stable_id("crewai", "research-crew"),
                name="Research Crew",
                organization_id=org,
                connector_type="crewai",
                raw_data={"agent_id": "research-crew", "framework": "crewai"},
            ),
        ]


class CrewAIStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.CREWAI

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {"crewai/crew": "ai_agent"}.get(resource_type)


# ─── AutoGen stub ─────────────────────────────────────────────────────────────


class AutoGenStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.AUTOGEN

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="autogen/agent",
                external_id=self._stable_id("autogen", "code-agent"),
                name="Code Execution Agent",
                organization_id=org,
                connector_type="autogen",
                raw_data={"agent_id": "code-agent", "framework": "autogen"},
            ),
        ]


class AutoGenStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.AUTOGEN

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {"autogen/agent": "ai_agent"}.get(resource_type)


# ─── OpenAI Agents SDK stub ───────────────────────────────────────────────────


class OpenAIAgentsSDKStubProvider(_BaseStubProvider):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.OPENAI_AGENTS_SDK

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="oai_agents/agent",
                external_id=self._stable_id("oai_agents", "triage-agent"),
                name="Triage Agent",
                organization_id=org,
                connector_type="openai_agents_sdk",
                raw_data={"agent_id": "triage-agent", "framework": "openai-agents-sdk"},
            ),
            RawResource(
                resource_type="oai_agents/tool",
                external_id=self._stable_id("oai_agents", "search-tool"),
                name="Search Tool",
                organization_id=org,
                connector_type="openai_agents_sdk",
                raw_data={"tool_name": "search", "tool_version": "1.0"},
            ),
        ]


class OpenAIAgentsSDKStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.OPENAI_AGENTS_SDK

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {
            "oai_agents/agent": "ai_agent",
            "oai_agents/tool": "tool_definition",
        }.get(resource_type)


# ─── MCP Registry stub ────────────────────────────────────────────────────────


class MCPRegistryStubProvider(_BaseStubProvider):
    """Stub for MCP Registry — discovers registered MCP servers and their tools."""

    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.MCP_REGISTRY

    def _synthetic_resources(
        self, connector: Connector, filters: dict[str, str]
    ) -> list[RawResource]:
        org = str(connector.organization_id)
        return [
            RawResource(
                resource_type="mcp/server",
                external_id=self._stable_id("mcp", "filesystem-server"),
                name="Filesystem MCP Server",
                organization_id=org,
                connector_type="mcp_registry",
                raw_data={
                    "server_id": "filesystem-server",
                    "protocol_version": "2025-03-26",
                    "transport": "stdio",
                    "tool_count": "5",
                },
            ),
            RawResource(
                resource_type="mcp/server",
                external_id=self._stable_id("mcp", "github-server"),
                name="GitHub MCP Server",
                organization_id=org,
                connector_type="mcp_registry",
                raw_data={
                    "server_id": "github-server",
                    "protocol_version": "2025-03-26",
                    "transport": "http",
                    "tool_count": "12",
                },
            ),
        ]


class MCPRegistryStubMapper(_BaseStubMapper):
    @property
    def connector_type(self) -> ConnectorType:
        return ConnectorType.MCP_REGISTRY

    def _resource_type_to_asset_type(self, resource_type: str) -> str | None:
        return {"mcp/server": "mcp_server"}.get(resource_type)


# ─── Registry factory ─────────────────────────────────────────────────────────


def build_default_registry() -> ConnectorRegistry:
    """Build and return a ConnectorRegistry pre-loaded with all stub providers."""
    registry = ConnectorRegistry()
    stubs: list[tuple[_BaseStubProvider, _BaseStubMapper]] = [
        (OpenAIStubProvider(), OpenAIStubMapper()),
        (AnthropicStubProvider(), AnthropicStubMapper()),
        (AzureOpenAIStubProvider(), AzureOpenAIStubMapper()),
        (AWSBedrockStubProvider(), AWSBedrockStubMapper()),
        (GoogleVertexAIStubProvider(), GoogleVertexAIStubMapper()),
        (LangSmithStubProvider(), LangSmithStubMapper()),
        (LangGraphStubProvider(), LangGraphStubMapper()),
        (CrewAIStubProvider(), CrewAIStubMapper()),
        (AutoGenStubProvider(), AutoGenStubMapper()),
        (OpenAIAgentsSDKStubProvider(), OpenAIAgentsSDKStubMapper()),
        (MCPRegistryStubProvider(), MCPRegistryStubMapper()),
    ]
    for provider, mapper in stubs:
        registry.register(provider, mapper)
    return registry

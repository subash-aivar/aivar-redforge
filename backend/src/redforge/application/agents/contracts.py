"""Protocol contracts for the Agent & MCP Validation Framework.

All collaborators injected into AgentValidationEngine and MCPValidationEngine
are defined here as @runtime_checkable Protocols.

Design rules (same as conversations/contracts.py):
- Protocols are @runtime_checkable
- No Protocol has a concrete default
- Application engine requires explicit wiring
- No framework leakage into protocol signatures
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.agents.entity import AgentSession, MCPSession
    from redforge.domain.agents.value_objects import (
        AgentBudget,
        MCPCapabilities,
        ToolInvocationRecord,
    )


# ─── DTOs ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AgentValidationRequest:
    """Everything AgentValidationEngine needs to start a session."""

    organization_id: str
    target_id: str
    agent_id: str
    target_endpoint: str
    target_provider: str
    target_system_prompt: str
    model: str
    attack_vectors: tuple[str, ...]           # AttackVector values
    tool_schemas: tuple[ToolSchemaDTO, ...]   # Tools available to the agent
    correlation_id: str
    budget: AgentBudget | None = None
    policy_id: str | None = None
    campaign_id: str | None = None
    mcp_server_url: str | None = None         # if agent uses MCP
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolSchemaDTO:
    """Serialisable tool schema for transport across layer boundaries."""

    name: str
    description: str
    parameters_json: str           # full JSON schema as a string
    risk_level: str = "unknown"    # ToolRiskLevel.value


@dataclass(frozen=True)
class AgentValidationResult:
    """What AgentValidationEngine returns after a session."""

    session_id: str
    organization_id: str
    status: str
    outcome: str | None
    total_tool_invocations: int
    blocked_invocations: int
    escalated_invocations: int
    attack_vectors_tested: int
    attack_vectors_succeeded: int
    max_depth_reached: int
    total_duration_ms: int
    failure_reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.attack_vectors_succeeded > 0


@dataclass(frozen=True)
class MCPValidationRequest:
    """Everything MCPValidationEngine needs to start an MCP session."""

    organization_id: str
    target_id: str
    mcp_server_id: str
    mcp_server_url: str
    attack_vectors: tuple[str, ...]
    correlation_id: str
    budget: AgentBudget | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MCPValidationResult:
    """What MCPValidationEngine returns after an MCP session."""

    session_id: str
    organization_id: str
    status: str
    outcome: str | None
    total_interactions: int
    attack_vectors_tested: int
    attack_vectors_succeeded: int
    failure_reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.attack_vectors_succeeded > 0


@dataclass(frozen=True)
class ToolCallContext:
    """Context available to ToolInvocationPolicy when evaluating a call."""

    session_id: str
    tool_name: str
    tool_call_id: str
    arguments: dict[str, Any]
    depth: int
    attack_vector: str
    prior_invocations: tuple[ToolInvocationRecord, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """Result of ToolInvocationPolicy.evaluate()."""

    action: str              # "allow" | "block" | "escalate" | "loop"
    rationale: str
    modified_arguments: dict[str, Any] | None = None  # for injection testing


@dataclass(frozen=True)
class MCPRequestContext:
    """Context for one MCP protocol request."""

    session_id: str
    mcp_server_id: str
    method: str              # "tools/call" | "resources/read" | "prompts/get"
    params: dict[str, Any]
    attack_vector: str
    interaction_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


# ─── Protocols ────────────────────────────────────────────────────────────────


@runtime_checkable
class AgentStrategyPort(Protocol):
    """Produces the attack payload for each step of an agent validation session.

    Analogous to ConversationStrategyPort but scoped to tool-calling contexts.
    first_step: called once to produce the opening user message.
    next_step: called after each tool result to produce the follow-up.
    """

    @property
    def name(self) -> str:
        ...

    def first_step(
        self,
        request: AgentValidationRequest,
        attack_vector: str,
    ) -> str:
        """Return the opening user message for this attack vector."""
        ...

    def next_step(
        self,
        request: AgentValidationRequest,
        attack_vector: str,
        messages: list[dict[str, Any]],
        last_tool_result: str,
    ) -> str | None:
        """Return the next user message, or None to terminate this vector."""
        ...


@runtime_checkable
class ToolInvocationPolicyPort(Protocol):
    """Decides whether a tool invocation should be allowed.

    The policy sees the tool call before it is executed (or simulated).
    It returns a PolicyDecision that the engine honours.
    """

    def evaluate(self, context: ToolCallContext) -> PolicyDecision:
        ...


@runtime_checkable
class ToolValidatorPort(Protocol):
    """Validates tool schemas for security issues.

    Checks:
    - Overly broad parameter types (injection surface)
    - Missing parameter validation
    - Dangerous capabilities declared
    - Schema inconsistencies
    """

    def validate_schema(self, schema: ToolSchemaDTO) -> list[str]:
        """Return list of security findings (empty = clean)."""
        ...


@runtime_checkable
class MCPTransportPort(Protocol):
    """Sends MCP wire-protocol messages to a server.

    RedForge ships a fake in-process transport for testing and a real
    stdio/SSE transport for production validation.
    """

    async def initialize(self, server_url: str) -> MCPCapabilities:
        """Perform the MCP initialize handshake."""
        ...

    async def list_tools(self) -> list[dict[str, Any]]:
        ...

    async def list_resources(self) -> list[dict[str, Any]]:
        ...

    async def list_prompts(self) -> list[dict[str, Any]]:
        ...

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        ...

    async def read_resource(self, uri: str) -> dict[str, Any]:
        ...

    async def get_prompt(
        self, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        ...

    async def close(self) -> None:
        ...


@runtime_checkable
class MCPInspectorPort(Protocol):
    """Analyses an MCP server's exposed surface for security vulnerabilities.

    Runs static analysis against declared tools/resources/prompts —
    no actual tool execution.
    """

    def inspect_tool_list(
        self, tools: list[dict[str, Any]]
    ) -> list[str]:
        """Return security findings about the tool surface."""
        ...

    def inspect_resource(
        self, uri: str, content: str
    ) -> list[str]:
        """Return security findings about a resource's content."""
        ...

    def inspect_prompt(
        self, name: str, template: str
    ) -> list[str]:
        """Return security findings about a prompt template."""
        ...


@runtime_checkable
class AgentSessionRepositoryPort(Protocol):
    """Persistence boundary for AgentSession aggregates."""

    async def save(self, session: AgentSession) -> None:
        ...

    async def get(self, session_id: str) -> AgentSession | None:
        ...


@runtime_checkable
class MCPSessionRepositoryPort(Protocol):
    """Persistence boundary for MCPSession aggregates."""

    async def save(self, session: MCPSession) -> None:
        ...

    async def get(self, session_id: str) -> MCPSession | None:
        ...


@runtime_checkable
class AgentKnowledgeProjectorPort(Protocol):
    """Projects AgentSession/MCPSession events into the Knowledge Graph."""

    def project_agent_session(self, session: AgentSession) -> int:
        """Project session node + edges. Returns nodes added."""
        ...

    def project_mcp_session(self, session: MCPSession) -> int:
        """Project MCP session node + edges. Returns nodes added."""
        ...

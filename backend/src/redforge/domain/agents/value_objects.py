"""Value objects for the Agent & MCP bounded context.

All value objects are frozen dataclasses or StrEnums.
None import from application, infrastructure, or api layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum, unique
from typing import Any

# ─── Status / lifecycle enums ─────────────────────────────────────────────────


@unique
class AgentSessionStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXHAUSTED = "exhausted"


@unique
class AgentSessionOutcome(StrEnum):
    SUCCESS = "success"       # at least one security finding reproduced
    FAILURE = "failure"       # no findings, target resisted all attacks
    PARTIAL = "partial"       # some attacks succeeded
    EXHAUSTED = "exhausted"   # budget hit before conclusion
    ERROR = "error"           # unhandled infrastructure failure


@unique
class ToolInvocationStatus(StrEnum):
    ALLOWED = "allowed"         # invocation passed all policies
    BLOCKED = "blocked"         # invocation blocked by policy
    TAMPERED = "tampered"       # result was modified in transit
    ESCALATED = "escalated"     # invocation exceeded granted permissions
    LOOPED = "looped"           # recursive/infinite loop detected
    ERROR = "error"             # executor error


@unique
class MCPSessionStatus(StrEnum):
    PENDING = "pending"
    CONNECTED = "connected"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"
    DISCONNECTED = "disconnected"


@unique
class MCPResourceType(StrEnum):
    TEXT = "text"
    BLOB = "blob"
    STRUCTURED = "structured"
    EMBEDDED = "embedded"
    EXTERNAL = "external"


@unique
class AgentCapabilityType(StrEnum):
    """What an agent under test can do — used to scope attack surface."""
    TOOL_CALLING = "tool_calling"
    FUNCTION_CALLING = "function_calling"
    MCP_CLIENT = "mcp_client"
    BROWSER_USE = "browser_use"
    COMPUTER_USE = "computer_use"
    CODE_EXECUTION = "code_execution"
    FILE_SYSTEM = "file_system"
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    EMAIL = "email"
    CALENDAR = "calendar"
    WEB_SEARCH = "web_search"
    MEMORY = "memory"
    MULTI_AGENT = "multi_agent"
    CUSTOM = "custom"


@unique
class ToolRiskLevel(StrEnum):
    """Risk classification for tools — drives attack prioritization."""
    CRITICAL = "critical"   # code execution, shell, file system write
    HIGH = "high"           # external API calls, email, calendar
    MEDIUM = "medium"       # read-only file, web search
    LOW = "low"             # internal computation, formatting
    UNKNOWN = "unknown"


@unique
class AttackVector(StrEnum):
    """The security attack being validated."""
    UNAUTHORIZED_INVOCATION = "unauthorized_invocation"
    PERMISSION_ESCALATION = "permission_escalation"
    TOOL_OUTPUT_INJECTION = "tool_output_injection"
    MCP_PROMPT_INJECTION = "mcp_prompt_injection"
    MCP_RESOURCE_POISONING = "mcp_resource_poisoning"
    TOOL_RESULT_TAMPERING = "tool_result_tampering"
    AGENT_MEMORY_ABUSE = "agent_memory_abuse"
    PLANNING_MANIPULATION = "planning_manipulation"
    RECURSIVE_TOOL_LOOP = "recursive_tool_loop"
    BROWSER_MISUSE = "browser_misuse"
    COMPUTER_USE_ABUSE = "computer_use_abuse"
    API_ABUSE = "api_abuse"
    CROSS_AGENT_ATTACK = "cross_agent_attack"
    TOOL_CHAIN_ATTACK = "tool_chain_attack"
    MCP_SERVER_SPOOFING = "mcp_server_spoofing"
    CAPABILITY_DISCOVERY = "capability_discovery"


# ─── Value object dataclasses ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ToolSchema:
    """JSON-schema-like description of a tool's parameters.

    We store a simplified representation here — the full JSON schema
    is in ``raw_schema`` for inspection/audit. RedForge never executes
    schemas directly; it only reads them to generate attack payloads.
    """

    name: str
    description: str
    parameters: tuple[str, ...]        # parameter names (for attack targeting)
    required_parameters: tuple[str, ...] = ()
    raw_schema: str = ""               # full JSON schema as a string


@dataclass(frozen=True, slots=True)
class ToolPermission:
    """What a tool is allowed to do — used for permission escalation detection."""

    can_read_filesystem: bool = False
    can_write_filesystem: bool = False
    can_execute_code: bool = False
    can_call_external_apis: bool = False
    can_access_database: bool = False
    can_send_email: bool = False
    can_access_browser: bool = False
    allowed_domains: tuple[str, ...] = ()
    allowed_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MCPCapabilities:
    """Declared capabilities of an MCP server.

    Populated from the ``initialize`` handshake response.
    """

    has_tools: bool = False
    has_resources: bool = False
    has_prompts: bool = False
    has_logging: bool = False
    has_sampling: bool = False
    protocol_version: str = "2024-11-05"
    server_name: str = ""
    server_version: str = ""


@dataclass(frozen=True, slots=True)
class AgentBudget:
    """Hard limits for one AgentSession validation run."""

    max_tool_invocations: int = 50
    max_depth: int = 10                # max recursive tool call depth
    max_duration_seconds: float = 300.0
    max_estimated_tokens: int = 100_000
    max_mcp_requests: int = 100


@dataclass(frozen=True, slots=True)
class ToolInvocationRecord:
    """Immutable record of a single tool call made during validation.

    Recorded by AgentSession.record_invocation(). Append-only.
    """

    invocation_id: str
    tool_name: str
    tool_call_id: str                  # provider-assigned ID (e.g. OpenAI call_xxx)
    arguments: str                     # JSON-serialised arguments
    result: str                        # JSON-serialised result (or error)
    status: str                        # ToolInvocationStatus.value
    attack_vector: str                 # AttackVector.value that triggered this
    depth: int = 0                     # recursion depth
    duration_ms: int = 0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return bool(self.error)

    @property
    def is_blocked(self) -> bool:
        return self.status == ToolInvocationStatus.BLOCKED.value


@dataclass(frozen=True, slots=True)
class MCPInteractionRecord:
    """One MCP request/response captured during validation."""

    interaction_id: str
    method: str                        # "tools/call" | "resources/read" | "prompts/get" etc.
    params: str                        # JSON-serialised params
    result: str                        # JSON-serialised result or error
    attack_vector: str                 # AttackVector.value
    duration_ms: int = 0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return bool(self.error)


@dataclass(frozen=True, slots=True)
class AgentSessionMetrics:
    """Computed metrics for a completed AgentSession."""

    total_tool_invocations: int
    blocked_invocations: int
    escalated_invocations: int
    looped_invocations: int
    tampered_invocations: int
    total_mcp_interactions: int
    attack_vectors_tested: int
    attack_vectors_succeeded: int
    max_depth_reached: int
    total_duration_ms: int
    total_estimated_tokens: int

    @property
    def block_rate(self) -> float:
        if self.total_tool_invocations == 0:
            return 0.0
        return self.blocked_invocations / self.total_tool_invocations

    @property
    def success_rate(self) -> float:
        if self.attack_vectors_tested == 0:
            return 0.0
        return self.attack_vectors_succeeded / self.attack_vectors_tested

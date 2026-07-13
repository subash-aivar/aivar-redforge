"""Domain events for the Agent & MCP bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # noqa: TC003 — used in frozen dataclass fields

from redforge.shared.timestamps import utc_now


def _now() -> datetime:
    return utc_now()


@dataclass(frozen=True, slots=True)
class AgentDomainEvent:
    session_id: str
    organization_id: str
    occurred_at: datetime = field(default_factory=_now)


# ─── AgentSession events ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AgentSessionCreated(AgentDomainEvent):
    agent_id: str = ""
    attack_vectors: tuple[str, ...] = ()
    max_tool_invocations: int = 0


@dataclass(frozen=True, slots=True)
class AgentSessionStarted(AgentDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ToolInvocationRecorded(AgentDomainEvent):
    invocation_id: str = ""
    tool_name: str = ""
    status: str = ""
    attack_vector: str = ""
    depth: int = 0


@dataclass(frozen=True, slots=True)
class MCPInteractionRecorded(AgentDomainEvent):
    interaction_id: str = ""
    method: str = ""
    attack_vector: str = ""


@dataclass(frozen=True, slots=True)
class ToolLoopDetected(AgentDomainEvent):
    tool_name: str = ""
    loop_depth: int = 0
    invocation_count: int = 0


@dataclass(frozen=True, slots=True)
class PermissionEscalationDetected(AgentDomainEvent):
    tool_name: str = ""
    invocation_id: str = ""
    requested_permission: str = ""


@dataclass(frozen=True, slots=True)
class AgentSessionCompleted(AgentDomainEvent):
    outcome: str = ""
    total_tool_invocations: int = 0
    attack_vectors_succeeded: int = 0
    success_rate: float = 0.0


@dataclass(frozen=True, slots=True)
class AgentSessionFailed(AgentDomainEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AgentSessionCancelled(AgentDomainEvent):
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AgentBudgetExhausted(AgentDomainEvent):
    exhaustion_reason: str = ""
    invocations_completed: int = 0


# ─── MCPSession events ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class MCPSessionConnected(AgentDomainEvent):
    mcp_server_id: str = ""
    protocol_version: str = ""
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MCPPromptInjectionDetected(AgentDomainEvent):
    resource_uri: str = ""
    injection_payload: str = ""


@dataclass(frozen=True, slots=True)
class MCPResourcePoisoningDetected(AgentDomainEvent):
    resource_uri: str = ""
    poison_type: str = ""


@dataclass(frozen=True, slots=True)
class MCPSessionCompleted(AgentDomainEvent):
    outcome: str = ""
    total_interactions: int = 0

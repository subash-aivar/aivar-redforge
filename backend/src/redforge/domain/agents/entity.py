"""AgentSession and MCPSession aggregate roots.

AgentSession:
  One validation run against an AI agent that uses tools/MCP.
  Records every tool invocation and MCP interaction for audit and analysis.
  Detects recursive loops, permission escalations, and budget exhaustion.

MCPSession:
  One validation run specifically targeting an MCP server.
  Records MCP protocol interactions (tools/call, resources/read, prompts/get).
  Tracks prompt injections and resource poisoning attempts.

Both aggregates follow the same lifecycle pattern as ConversationSession:
PENDING → RUNNING → {COMPLETED, FAILED, CANCELLED, EXHAUSTED}

Domain layer — imports only domain.*, shared.*, core.exceptions (ADR-0001).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.agents.events import (
    AgentBudgetExhausted,
    AgentDomainEvent,
    AgentSessionCancelled,
    AgentSessionCompleted,
    AgentSessionCreated,
    AgentSessionFailed,
    AgentSessionStarted,
    MCPInteractionRecorded,
    MCPSessionCompleted,
    MCPSessionConnected,
    PermissionEscalationDetected,
    ToolInvocationRecorded,
    ToolLoopDetected,
)
from redforge.domain.agents.exceptions import (
    AgentSessionAlreadyTerminalError,
    AgentSessionNotRunningError,
    InvalidAgentSessionTransitionError,
)
from redforge.domain.agents.value_objects import (
    AgentBudget,
    AgentCapabilityType,
    AgentSessionMetrics,
    AgentSessionOutcome,
    AgentSessionStatus,
    AttackVector,
    MCPCapabilities,
    MCPInteractionRecord,
    MCPSessionStatus,
    ToolInvocationRecord,
    ToolInvocationStatus,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps, utc_now

if TYPE_CHECKING:
    from datetime import datetime

_TERMINAL = frozenset({
    AgentSessionStatus.COMPLETED,
    AgentSessionStatus.FAILED,
    AgentSessionStatus.CANCELLED,
    AgentSessionStatus.EXHAUSTED,
})

# Max same-tool calls before a loop is declared
_LOOP_REPETITION_THRESHOLD = 5


class AgentSession:
    """Aggregate root for one agent security validation session.

    Records:
    - Tool invocations (in order, append-only)
    - MCP interactions (in order, append-only)
    - Detected security events (loop, escalation, injection)

    The application layer (AgentValidationEngine) drives all state transitions.
    This aggregate only records what happened.
    """

    __slots__ = (
        "_agent_id",
        "_attack_vectors",
        "_budget",
        "_campaign_id",
        "_capabilities",
        "_completed_at",
        "_events",
        "_failure_reason",
        "_id",
        "_invocations",
        "_mcp_interactions",
        "_metadata",
        "_metrics",
        "_organization_id",
        "_outcome",
        "_policy_id",
        "_started_at",
        "_status",
        "_succeeded_vectors",
        "_target_id",
        "_timestamps",
        "_tool_call_depth",
        "_tool_invocation_counts",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        agent_id: str,
        attack_vectors: tuple[AttackVector, ...],
        capabilities: tuple[AgentCapabilityType, ...],
        budget: AgentBudget,
        status: AgentSessionStatus,
        invocations: tuple[ToolInvocationRecord, ...],
        mcp_interactions: tuple[MCPInteractionRecord, ...],
        outcome: AgentSessionOutcome | None,
        metrics: AgentSessionMetrics | None,
        succeeded_vectors: frozenset[str],
        policy_id: EntityId | None,
        campaign_id: EntityId | None,
        started_at: datetime | None,
        completed_at: datetime | None,
        failure_reason: str | None,
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._agent_id = agent_id
        self._attack_vectors = attack_vectors
        self._capabilities = capabilities
        self._budget = budget
        self._status = status
        self._invocations = invocations
        self._mcp_interactions = mcp_interactions
        self._outcome = outcome
        self._metrics = metrics
        self._succeeded_vectors = succeeded_vectors
        self._policy_id = policy_id
        self._campaign_id = campaign_id
        self._started_at = started_at
        self._completed_at = completed_at
        self._failure_reason = failure_reason
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[AgentDomainEvent] = []
        # Live tracking (not persisted as fields — derived at runtime)
        self._tool_invocation_counts: dict[str, int] = {}
        self._tool_call_depth: int = 0

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        agent_id: str,
        attack_vectors: tuple[AttackVector, ...],
        capabilities: tuple[AgentCapabilityType, ...] = (),
        budget: AgentBudget | None = None,
        policy_id: EntityId | None = None,
        campaign_id: EntityId | None = None,
        metadata: dict[str, str] | None = None,
    ) -> AgentSession:
        if not agent_id:
            from redforge.core.exceptions import ValidationError
            raise ValidationError("agent_id must not be empty")
        if not attack_vectors:
            from redforge.core.exceptions import ValidationError
            raise ValidationError("at least one attack_vector must be specified")

        session_id = EntityId.generate()
        effective_budget = budget or AgentBudget()

        session = cls(
            id=session_id,
            organization_id=organization_id,
            target_id=target_id,
            agent_id=agent_id,
            attack_vectors=attack_vectors,
            capabilities=capabilities,
            budget=effective_budget,
            status=AgentSessionStatus.PENDING,
            invocations=(),
            mcp_interactions=(),
            outcome=None,
            metrics=None,
            succeeded_vectors=frozenset(),
            policy_id=policy_id,
            campaign_id=campaign_id,
            started_at=None,
            completed_at=None,
            failure_reason=None,
            metadata=metadata or {},
            timestamps=AuditTimestamps.create(),
        )
        session._events.append(AgentSessionCreated(
            session_id=str(session_id),
            organization_id=str(organization_id),
            agent_id=agent_id,
            attack_vectors=tuple(v.value for v in attack_vectors),
            max_tool_invocations=effective_budget.max_tool_invocations,
        ))
        return session

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def attack_vectors(self) -> tuple[AttackVector, ...]:
        return self._attack_vectors

    @property
    def capabilities(self) -> tuple[AgentCapabilityType, ...]:
        return self._capabilities

    @property
    def budget(self) -> AgentBudget:
        return self._budget

    @property
    def status(self) -> AgentSessionStatus:
        return self._status

    @property
    def invocations(self) -> tuple[ToolInvocationRecord, ...]:
        return self._invocations

    @property
    def mcp_interactions(self) -> tuple[MCPInteractionRecord, ...]:
        return self._mcp_interactions

    @property
    def outcome(self) -> AgentSessionOutcome | None:
        return self._outcome

    @property
    def metrics(self) -> AgentSessionMetrics | None:
        return self._metrics

    @property
    def succeeded_vectors(self) -> frozenset[str]:
        return self._succeeded_vectors

    @property
    def policy_id(self) -> EntityId | None:
        return self._policy_id

    @property
    def campaign_id(self) -> EntityId | None:
        return self._campaign_id

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def completed_at(self) -> datetime | None:
        return self._completed_at

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_terminal(self) -> bool:
        return self._status in _TERMINAL

    @property
    def is_running(self) -> bool:
        return self._status == AgentSessionStatus.RUNNING

    @property
    def invocation_count(self) -> int:
        return len(self._invocations)

    @property
    def current_depth(self) -> int:
        return self._tool_call_depth

    @property
    def budget_remaining_invocations(self) -> int:
        return max(0, self._budget.max_tool_invocations - len(self._invocations))

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._status != AgentSessionStatus.PENDING:
            raise InvalidAgentSessionTransitionError(self._status.value, "running")
        self._status = AgentSessionStatus.RUNNING
        self._started_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(AgentSessionStarted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
        ))

    def record_invocation(
        self,
        invocation: ToolInvocationRecord,
        mark_vector_succeeded: bool = False,
    ) -> None:
        """Append one tool invocation. Checks loop detection and budget."""
        if self._status != AgentSessionStatus.RUNNING:
            raise AgentSessionNotRunningError(str(self._id), self._status.value)

        # Loop detection: same tool called too many times
        count = self._tool_invocation_counts.get(invocation.tool_name, 0) + 1
        self._tool_invocation_counts[invocation.tool_name] = count
        if count >= _LOOP_REPETITION_THRESHOLD:
            self._events.append(ToolLoopDetected(
                session_id=str(self._id),
                organization_id=str(self._organization_id),
                tool_name=invocation.tool_name,
                loop_depth=invocation.depth,
                invocation_count=count,
            ))

        # Depth tracking
        self._tool_call_depth = max(self._tool_call_depth, invocation.depth)

        self._invocations = (*self._invocations, invocation)
        self._timestamps = self._timestamps.mark_updated()

        # Permission escalation event
        if invocation.status == ToolInvocationStatus.ESCALATED.value:
            self._events.append(PermissionEscalationDetected(
                session_id=str(self._id),
                organization_id=str(self._organization_id),
                tool_name=invocation.tool_name,
                invocation_id=invocation.invocation_id,
                requested_permission=invocation.attack_vector,
            ))

        # Mark succeeded attack vector
        if mark_vector_succeeded:
            self._succeeded_vectors = self._succeeded_vectors | {invocation.attack_vector}

        self._events.append(ToolInvocationRecorded(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            invocation_id=invocation.invocation_id,
            tool_name=invocation.tool_name,
            status=invocation.status,
            attack_vector=invocation.attack_vector,
            depth=invocation.depth,
        ))

    def record_mcp_interaction(
        self,
        interaction: MCPInteractionRecord,
        mark_vector_succeeded: bool = False,
    ) -> None:
        """Append one MCP interaction."""
        if self._status != AgentSessionStatus.RUNNING:
            raise AgentSessionNotRunningError(str(self._id), self._status.value)
        self._mcp_interactions = (*self._mcp_interactions, interaction)
        self._timestamps = self._timestamps.mark_updated()
        if mark_vector_succeeded:
            self._succeeded_vectors = self._succeeded_vectors | {interaction.attack_vector}
        self._events.append(MCPInteractionRecorded(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            interaction_id=interaction.interaction_id,
            method=interaction.method,
            attack_vector=interaction.attack_vector,
        ))

    def complete(self, outcome: AgentSessionOutcome) -> None:
        if self.is_terminal:
            raise AgentSessionAlreadyTerminalError(str(self._id), self._status.value)
        if self._status != AgentSessionStatus.RUNNING:
            raise InvalidAgentSessionTransitionError(self._status.value, "completed")
        self._status = AgentSessionStatus.COMPLETED
        self._outcome = outcome
        self._metrics = _compute_metrics(self)
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(AgentSessionCompleted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            outcome=outcome.value,
            total_tool_invocations=len(self._invocations),
            attack_vectors_succeeded=len(self._succeeded_vectors),
            success_rate=self._metrics.success_rate,
        ))

    def exhaust_budget(self, reason: str) -> None:
        if self.is_terminal:
            raise AgentSessionAlreadyTerminalError(str(self._id), self._status.value)
        if self._status != AgentSessionStatus.RUNNING:
            raise InvalidAgentSessionTransitionError(self._status.value, "exhausted")
        self._status = AgentSessionStatus.EXHAUSTED
        self._outcome = AgentSessionOutcome.EXHAUSTED
        self._metrics = _compute_metrics(self)
        self._failure_reason = reason
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(AgentBudgetExhausted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            exhaustion_reason=reason,
            invocations_completed=len(self._invocations),
        ))

    def fail(self, reason: str) -> None:
        if self.is_terminal:
            raise AgentSessionAlreadyTerminalError(str(self._id), self._status.value)
        self._status = AgentSessionStatus.FAILED
        self._failure_reason = reason
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(AgentSessionFailed(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            reason=reason,
        ))

    def cancel(self, reason: str = "") -> None:
        if self.is_terminal:
            raise AgentSessionAlreadyTerminalError(str(self._id), self._status.value)
        self._status = AgentSessionStatus.CANCELLED
        self._failure_reason = reason or "cancelled"
        self._completed_at = utc_now()
        self._timestamps = self._timestamps.mark_updated()
        self._events.append(AgentSessionCancelled(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            reason=self._failure_reason,
        ))

    def collect_events(self) -> list[AgentDomainEvent]:
        events, self._events = self._events, []
        return events

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AgentSession):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"AgentSession(id={self._id!s}, agent={self._agent_id!r}, "
            f"status={self._status.value}, "
            f"invocations={len(self._invocations)}/{self._budget.max_tool_invocations})"
        )


class MCPSession:
    """Aggregate root for one MCP server validation session.

    Tracks the full MCP protocol exchange: initialization, tool listing,
    resource listing, prompt retrieval, and targeted attack calls.
    """

    __slots__ = (
        "_attack_vectors",
        "_budget",
        "_capabilities",
        "_completed_at",
        "_events",
        "_failure_reason",
        "_id",
        "_interactions",
        "_mcp_server_id",
        "_metadata",
        "_organization_id",
        "_outcome",
        "_started_at",
        "_status",
        "_succeeded_vectors",
        "_target_id",
        "_timestamps",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        target_id: EntityId,
        mcp_server_id: str,
        attack_vectors: tuple[AttackVector, ...],
        capabilities: MCPCapabilities,
        budget: AgentBudget,
        status: MCPSessionStatus,
        interactions: tuple[MCPInteractionRecord, ...],
        outcome: AgentSessionOutcome | None,
        succeeded_vectors: frozenset[str],
        started_at: datetime | None,
        completed_at: datetime | None,
        failure_reason: str | None,
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._target_id = target_id
        self._mcp_server_id = mcp_server_id
        self._attack_vectors = attack_vectors
        self._capabilities = capabilities
        self._budget = budget
        self._status = status
        self._interactions = interactions
        self._outcome = outcome
        self._succeeded_vectors = succeeded_vectors
        self._started_at = started_at
        self._completed_at = completed_at
        self._failure_reason = failure_reason
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[AgentDomainEvent] = []

    @classmethod
    def create(
        cls,
        organization_id: EntityId,
        target_id: EntityId,
        mcp_server_id: str,
        attack_vectors: tuple[AttackVector, ...],
        capabilities: MCPCapabilities | None = None,
        budget: AgentBudget | None = None,
        metadata: dict[str, str] | None = None,
    ) -> MCPSession:
        if not mcp_server_id:
            from redforge.core.exceptions import ValidationError
            raise ValidationError("mcp_server_id must not be empty")

        session_id = EntityId.generate()
        return cls(
            id=session_id,
            organization_id=organization_id,
            target_id=target_id,
            mcp_server_id=mcp_server_id,
            attack_vectors=attack_vectors,
            capabilities=capabilities or MCPCapabilities(),
            budget=budget or AgentBudget(),
            status=MCPSessionStatus.PENDING,
            interactions=(),
            outcome=None,
            succeeded_vectors=frozenset(),
            started_at=None,
            completed_at=None,
            failure_reason=None,
            metadata=metadata or {},
            timestamps=AuditTimestamps.create(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def mcp_server_id(self) -> str:
        return self._mcp_server_id

    @property
    def status(self) -> MCPSessionStatus:
        return self._status

    @property
    def interactions(self) -> tuple[MCPInteractionRecord, ...]:
        return self._interactions

    @property
    def outcome(self) -> AgentSessionOutcome | None:
        return self._outcome

    @property
    def succeeded_vectors(self) -> frozenset[str]:
        return self._succeeded_vectors

    @property
    def attack_vectors(self) -> tuple[AttackVector, ...]:
        return self._attack_vectors

    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason

    @property
    def capabilities(self) -> MCPCapabilities:
        return self._capabilities

    @property
    def is_terminal(self) -> bool:
        return self._status in {
            MCPSessionStatus.COMPLETED,
            MCPSessionStatus.FAILED,
        }

    def connect(self, capabilities: MCPCapabilities) -> None:
        if self._status != MCPSessionStatus.PENDING:
            raise InvalidAgentSessionTransitionError(self._status.value, "connected")
        self._status = MCPSessionStatus.CONNECTED
        self._capabilities = capabilities
        self._started_at = utc_now()
        self._events.append(MCPSessionConnected(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            mcp_server_id=self._mcp_server_id,
            protocol_version=capabilities.protocol_version,
            capabilities=tuple(
                k for k, v in {
                    "tools": capabilities.has_tools,
                    "resources": capabilities.has_resources,
                    "prompts": capabilities.has_prompts,
                }.items() if v
            ),
        ))

    def record_interaction(
        self,
        interaction: MCPInteractionRecord,
        mark_vector_succeeded: bool = False,
    ) -> None:
        self._interactions = (*self._interactions, interaction)
        if mark_vector_succeeded:
            self._succeeded_vectors = self._succeeded_vectors | {interaction.attack_vector}
        self._events.append(MCPInteractionRecorded(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            interaction_id=interaction.interaction_id,
            method=interaction.method,
            attack_vector=interaction.attack_vector,
        ))

    def complete(self, outcome: AgentSessionOutcome) -> None:
        if self.is_terminal:
            raise AgentSessionAlreadyTerminalError(str(self._id), self._status.value)
        self._status = MCPSessionStatus.COMPLETED
        self._outcome = outcome
        self._completed_at = utc_now()
        self._events.append(MCPSessionCompleted(
            session_id=str(self._id),
            organization_id=str(self._organization_id),
            outcome=outcome.value,
            total_interactions=len(self._interactions),
        ))

    def fail(self, reason: str) -> None:
        if self.is_terminal:
            raise AgentSessionAlreadyTerminalError(str(self._id), self._status.value)
        self._status = MCPSessionStatus.FAILED
        self._failure_reason = reason
        self._completed_at = utc_now()

    def collect_events(self) -> list[AgentDomainEvent]:
        events, self._events = self._events, []
        return events

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MCPSession):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)


# ─── Internal helpers ─────────────────────────────────────────────────────────


def _compute_metrics(session: AgentSession) -> AgentSessionMetrics:
    invocations = session.invocations
    mcp = session.mcp_interactions

    blocked = sum(1 for i in invocations if i.is_blocked)
    escalated = sum(
        1 for i in invocations
        if i.status == ToolInvocationStatus.ESCALATED.value
    )
    looped = sum(
        1 for i in invocations
        if i.status == ToolInvocationStatus.LOOPED.value
    )
    tampered = sum(
        1 for i in invocations
        if i.status == ToolInvocationStatus.TAMPERED.value
    )
    max_depth = max((i.depth for i in invocations), default=0)
    total_ms = sum(i.duration_ms for i in invocations)
    total_tokens = 0  # estimated by engine, passed via metadata

    return AgentSessionMetrics(
        total_tool_invocations=len(invocations),
        blocked_invocations=blocked,
        escalated_invocations=escalated,
        looped_invocations=looped,
        tampered_invocations=tampered,
        total_mcp_interactions=len(mcp),
        attack_vectors_tested=len(session.attack_vectors),
        attack_vectors_succeeded=len(session.succeeded_vectors),
        max_depth_reached=max_depth,
        total_duration_ms=total_ms,
        total_estimated_tokens=total_tokens,
    )

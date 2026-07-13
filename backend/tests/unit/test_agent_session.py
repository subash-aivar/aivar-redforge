"""Unit tests for AgentSession and MCPSession aggregate roots."""

from __future__ import annotations

import pytest

from redforge.domain.agents.entity import AgentSession, MCPSession
from redforge.domain.agents.exceptions import (
    AgentSessionAlreadyTerminalError,
    AgentSessionNotRunningError,
    InvalidAgentSessionTransitionError,
)
from redforge.domain.agents.value_objects import (
    AgentBudget,
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

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _org() -> EntityId:
    return EntityId.generate()


def _target() -> EntityId:
    return EntityId.generate()


def _agent_session(
    vectors: tuple[AttackVector, ...] = (AttackVector.UNAUTHORIZED_INVOCATION,),
    budget: AgentBudget | None = None,
) -> AgentSession:
    return AgentSession.create(
        organization_id=_org(),
        target_id=_target(),
        agent_id="test-agent",
        attack_vectors=vectors,
        budget=budget,
    )


def _mcp_session() -> MCPSession:
    return MCPSession.create(
        organization_id=_org(),
        target_id=_target(),
        mcp_server_id="test-mcp-server",
        attack_vectors=(AttackVector.MCP_PROMPT_INJECTION,),
    )


def _invocation(
    tool_name: str = "search",
    status: str = ToolInvocationStatus.ALLOWED.value,
    attack_vector: str = AttackVector.UNAUTHORIZED_INVOCATION.value,
    depth: int = 1,
) -> ToolInvocationRecord:
    return ToolInvocationRecord(
        invocation_id=str(EntityId.generate()),
        tool_name=tool_name,
        tool_call_id=str(EntityId.generate()),
        arguments="{}",
        result="{}",
        status=status,
        attack_vector=attack_vector,
        depth=depth,
    )


def _mcp_interaction(
    method: str = "tools/call",
    attack_vector: str = AttackVector.MCP_PROMPT_INJECTION.value,
) -> MCPInteractionRecord:
    return MCPInteractionRecord(
        interaction_id=str(EntityId.generate()),
        method=method,
        params="{}",
        result="{}",
        attack_vector=attack_vector,
    )


# ─── AgentSession lifecycle ───────────────────────────────────────────────────


class TestAgentSessionLifecycle:
    def test_create_produces_pending_session(self) -> None:
        s = _agent_session()
        assert s.status == AgentSessionStatus.PENDING
        assert s.outcome is None
        assert s.invocation_count == 0

    def test_start_transitions_to_running(self) -> None:
        s = _agent_session()
        s.start()
        assert s.status == AgentSessionStatus.RUNNING
        assert s.is_running

    def test_start_on_non_pending_raises(self) -> None:
        s = _agent_session()
        s.start()
        with pytest.raises(InvalidAgentSessionTransitionError):
            s.start()

    def test_complete_transitions_to_completed(self) -> None:
        s = _agent_session()
        s.start()
        s.complete(AgentSessionOutcome.SUCCESS)
        assert s.status == AgentSessionStatus.COMPLETED
        assert s.outcome == AgentSessionOutcome.SUCCESS
        assert s.is_terminal

    def test_fail_transitions_to_failed(self) -> None:
        s = _agent_session()
        s.start()
        s.fail("network error")
        assert s.status == AgentSessionStatus.FAILED
        assert s.failure_reason == "network error"

    def test_cancel_transitions_to_cancelled(self) -> None:
        s = _agent_session()
        s.start()
        s.cancel("user cancelled")
        assert s.status == AgentSessionStatus.CANCELLED

    def test_complete_on_terminal_raises(self) -> None:
        s = _agent_session()
        s.start()
        s.fail("oops")
        with pytest.raises(AgentSessionAlreadyTerminalError):
            s.complete(AgentSessionOutcome.SUCCESS)

    def test_exhaust_budget_transitions_to_exhausted(self) -> None:
        s = _agent_session()
        s.start()
        s.exhaust_budget("max_tool_invocations=50 reached")
        assert s.status == AgentSessionStatus.EXHAUSTED
        assert s.outcome == AgentSessionOutcome.EXHAUSTED

    def test_record_invocation_while_not_running_raises(self) -> None:
        s = _agent_session()
        with pytest.raises(AgentSessionNotRunningError):
            s.record_invocation(_invocation())


# ─── AgentSession invocations ─────────────────────────────────────────────────


class TestAgentSessionInvocations:
    def test_record_invocation_appends(self) -> None:
        s = _agent_session()
        s.start()
        s.record_invocation(_invocation("search"))
        assert s.invocation_count == 1

    def test_invocations_are_immutable_tuple(self) -> None:
        s = _agent_session()
        s.start()
        s.record_invocation(_invocation("a"))
        s.record_invocation(_invocation("b"))
        assert len(s.invocations) == 2
        # tuple — cannot append externally
        with pytest.raises((TypeError, AttributeError)):
            s.invocations.append(_invocation("c"))  # type: ignore[attr-defined]

    def test_mark_vector_succeeded_tracks_succeeded(self) -> None:
        s = _agent_session()
        s.start()
        inv = _invocation(
            attack_vector=AttackVector.UNAUTHORIZED_INVOCATION.value,
            status=ToolInvocationStatus.ESCALATED.value,
        )
        s.record_invocation(inv, mark_vector_succeeded=True)
        assert AttackVector.UNAUTHORIZED_INVOCATION.value in s.succeeded_vectors

    def test_metrics_populated_after_complete(self) -> None:
        s = _agent_session()
        s.start()
        s.record_invocation(_invocation(status=ToolInvocationStatus.BLOCKED.value))
        s.complete(AgentSessionOutcome.SUCCESS)
        assert s.metrics is not None
        assert s.metrics.blocked_invocations == 1

    def test_events_emitted_and_collected(self) -> None:
        s = _agent_session()
        s.start()
        s.record_invocation(_invocation())
        events = s.collect_events()
        assert len(events) >= 2  # Created + Started + ToolInvocationRecorded


# ─── Loop detection ───────────────────────────────────────────────────────────


class TestLoopDetection:
    def test_same_tool_five_times_emits_loop_event(self) -> None:
        s = _agent_session()
        s.start()
        for _ in range(5):
            s.record_invocation(_invocation("calculator"))
        events = s.collect_events()
        loop_events = [e for e in events if "loop" in type(e).__name__.lower()]
        assert loop_events, "ToolLoopDetected event must be emitted at threshold"

    def test_different_tools_do_not_trigger_loop(self) -> None:
        s = _agent_session()
        s.start()
        for name in ["a", "b", "c", "d", "e"]:
            s.record_invocation(_invocation(name))
        events = s.collect_events()
        loop_events = [e for e in events if "loop" in type(e).__name__.lower()]
        assert not loop_events


# ─── MCPSession lifecycle ─────────────────────────────────────────────────────


class TestMCPSessionLifecycle:
    def test_create_produces_pending_session(self) -> None:
        s = _mcp_session()
        assert s.status == MCPSessionStatus.PENDING
        assert s.outcome is None

    def test_connect_transitions_to_connected(self) -> None:
        s = _mcp_session()
        caps = MCPCapabilities(has_tools=True, has_resources=True)
        s.connect(caps)
        assert s.status == MCPSessionStatus.CONNECTED
        assert s.capabilities.has_tools

    def test_record_interaction_appends(self) -> None:
        s = _mcp_session()
        caps = MCPCapabilities()
        s.connect(caps)
        s.record_interaction(_mcp_interaction())
        assert len(s.interactions) == 1

    def test_mark_vector_succeeded(self) -> None:
        s = _mcp_session()
        s.connect(MCPCapabilities())
        interaction = _mcp_interaction(
            attack_vector=AttackVector.MCP_PROMPT_INJECTION.value
        )
        s.record_interaction(interaction, mark_vector_succeeded=True)
        assert AttackVector.MCP_PROMPT_INJECTION.value in s.succeeded_vectors

    def test_complete(self) -> None:
        s = _mcp_session()
        s.connect(MCPCapabilities())
        s.complete(AgentSessionOutcome.SUCCESS)
        assert s.status == MCPSessionStatus.COMPLETED
        assert s.is_terminal

    def test_fail(self) -> None:
        s = _mcp_session()
        s.connect(MCPCapabilities())
        s.fail("transport error")
        assert s.status == MCPSessionStatus.FAILED
        assert s.failure_reason == "transport error"

    def test_fail_on_terminal_raises(self) -> None:
        s = _mcp_session()
        s.connect(MCPCapabilities())
        s.complete(AgentSessionOutcome.FAILURE)
        with pytest.raises(AgentSessionAlreadyTerminalError):
            s.fail("too late")

    def test_attack_vectors_exposed(self) -> None:
        s = _mcp_session()
        assert AttackVector.MCP_PROMPT_INJECTION in s.attack_vectors

    def test_connect_on_non_pending_raises(self) -> None:
        s = _mcp_session()
        s.connect(MCPCapabilities())
        with pytest.raises(InvalidAgentSessionTransitionError):
            s.connect(MCPCapabilities())


# ─── Budget ───────────────────────────────────────────────────────────────────


class TestAgentSessionBudget:
    def test_budget_remaining_decrements(self) -> None:
        budget = AgentBudget(max_tool_invocations=5)
        s = _agent_session(budget=budget)
        s.start()
        assert s.budget_remaining_invocations == 5
        s.record_invocation(_invocation())
        assert s.budget_remaining_invocations == 4

    def test_default_budget(self) -> None:
        s = _agent_session()
        assert s.budget.max_tool_invocations == 50
        assert s.budget.max_depth == 10

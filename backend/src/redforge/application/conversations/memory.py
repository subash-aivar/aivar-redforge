"""Conversation memory subsystem.

Three layers:
- WorkingMemory: per-turn scratch space (message list, observations) — discarded when
  ConversationEngine finishes.
- ConversationMemory: across-turn accumulation for one session — attached to a session_id.
- InMemoryCheckpointStore: in-process checkpoint implementation (useful for tests and
  short-lived processes; production deployments wire a persistent store).

Memory stores are NOT domain objects — they live in the application layer and are
injected into ConversationEngine.

Nothing here calls an LLM. Memory is read/written by the engine and strategies.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

# ─── Working memory ───────────────────────────────────────────────────────────


@dataclass
class WorkingMemory:
    """Mutable per-session scratch space used by ConversationEngine during a session.

    messages: OpenAI-format message list — grows as turns are executed.
    observations: strings extracted from responses by the decision engine.
    attempted_payloads: set of payload hashes seen in this session (dedup).
    """

    messages: list[dict[str, Any]] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    attempted_payloads: set[str] = field(default_factory=set)
    _max_observations: int = 100

    def append_message(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})

    def add_observation(self, obs: str) -> None:
        if obs and len(self.observations) < self._max_observations:
            self.observations.append(obs)

    def add_observations(self, obs: tuple[str, ...]) -> None:
        for o in obs:
            self.add_observation(o)

    def mark_payload(self, payload_hash: str) -> None:
        self.attempted_payloads.add(payload_hash)

    def is_duplicate(self, payload_hash: str) -> bool:
        return payload_hash in self.attempted_payloads

    def snapshot_messages(self) -> list[dict[str, Any]]:
        return list(self.messages)

    def snapshot_observations(self) -> list[str]:
        return list(self.observations)

    def reset_for_pivot(self, keep_system: bool = True) -> None:
        """Clear message history on PIVOT (restart conversation thread)."""
        if keep_system and self.messages and self.messages[0]["role"] == "system":
            system_msg = self.messages[0]
            self.messages = [system_msg]
        else:
            self.messages = []


# ─── Conversation memory ──────────────────────────────────────────────────────


@dataclass
class ConversationMemory:
    """Accumulates knowledge about a conversation across turns.

    Used by strategies and the decision engine to query what has been tried.
    Not persisted — in-process only. For cross-session persistence, use
    ConversationCheckpointStorePort.
    """

    session_id: str
    _max_response_cache: int = 10
    _recent_responses: deque[str] = field(default_factory=lambda: deque(maxlen=10))
    _strategy_outcomes: dict[str, list[str]] = field(default_factory=dict)
    _all_observations: list[str] = field(default_factory=list)

    def record_response(self, turn_number: int, response: str) -> None:
        self._recent_responses.append(response)

    def record_strategy_outcome(self, strategy: str, outcome: str) -> None:
        self._strategy_outcomes.setdefault(strategy, []).append(outcome)

    def record_observations(self, observations: tuple[str, ...]) -> None:
        self._all_observations.extend(observations)

    @property
    def recent_responses(self) -> list[str]:
        return list(self._recent_responses)

    @property
    def all_observations(self) -> list[str]:
        return list(self._all_observations)

    def strategy_outcomes(self, strategy: str) -> list[str]:
        return list(self._strategy_outcomes.get(strategy, []))

    def has_succeeded(self) -> bool:
        return any(
            any(o in outcomes for o in ("success", "terminate_success"))
            for outcomes in self._strategy_outcomes.values()
        )


# ─── In-memory checkpoint store ───────────────────────────────────────────────


class InMemoryCheckpointStore:
    """In-process checkpoint store — suitable for tests and short-lived jobs.

    Production deployments should use a database-backed implementation.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[int, list[dict[str, Any]], list[str]]] = {}

    async def save_checkpoint(
        self,
        session_id: str,
        turn_number: int,
        messages: list[dict[str, Any]],
        observations: list[str],
    ) -> None:
        self._store[session_id] = (turn_number, list(messages), list(observations))

    async def load_checkpoint(
        self, session_id: str
    ) -> tuple[int, list[dict[str, Any]], list[str]] | None:
        return self._store.get(session_id)

    def clear(self, session_id: str) -> None:
        self._store.pop(session_id, None)

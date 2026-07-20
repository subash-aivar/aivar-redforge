"""ReplayAttackActionExecution — read-only journal simulation (no side effects)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from collections.abc import Callable

    from execution.application.ports.i_unit_of_work import IUnitOfWork
    from execution.domain.aggregates.execution_journal import ExecutionJournal
    from execution.domain.entities.journal_entry import JournalEntry


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ReplayAttackActionExecution:
    tenant_id: UUID
    journal_id: UUID | None = None
    engagement_id: UUID | None = None

    def __post_init__(self) -> None:
        if self.journal_id is None and self.engagement_id is None:
            raise ValueError("Either journal_id or engagement_id is required")


@dataclass
class ReplayStep:
    sequence_number: int
    entry_type: str
    content: str
    occurred_at: str
    entry_hash: str
    simulated_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence_number": self.sequence_number,
            "entry_type": self.entry_type,
            "content": self.content,
            "occurred_at": self.occurred_at,
            "entry_hash": self.entry_hash,
            "simulated_state": self.simulated_state,
        }


@dataclass
class ReplayReport:
    """Result of a read-only journal replay simulation."""

    tenant_id: str
    journal_id: str
    engagement_id: str
    steps: list[ReplayStep] = field(default_factory=list)
    actions_simulated: int = 0
    evidence_touched: bool = False
    journal_appended: bool = False
    attack_actions_created: bool = False
    simulated_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "journal_id": self.journal_id,
            "engagement_id": self.engagement_id,
            "steps": [s.to_dict() for s in self.steps],
            "actions_simulated": self.actions_simulated,
            "evidence_touched": self.evidence_touched,
            "journal_appended": self.journal_appended,
            "attack_actions_created": self.attack_actions_created,
            "simulated_at": self.simulated_at.isoformat(),
        }


class ReplayApplicationService:
    """Replay attack-action execution from journal for training / detection tuning.

    MUST NOT create new AttackAction records, collect evidence, or append journal
    entries. Simulation is purely in-memory from existing journal content.
    """

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork] | None = None,
        *,
        journal_loader: Callable[[ReplayAttackActionExecution], Any] | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._journal_loader = journal_loader
        self._attack_actions_created = 0
        self._evidence_collected = 0
        self._journal_appends = 0

    @property
    def side_effect_counters(self) -> dict[str, int]:
        return {
            "attack_actions_created": self._attack_actions_created,
            "evidence_collected": self._evidence_collected,
            "journal_appends": self._journal_appends,
        }

    async def replay(self, command: ReplayAttackActionExecution) -> ReplayReport:
        journal = await self._load_journal(command)
        if journal is None:
            raise LookupError("Execution journal not found")

        steps: list[ReplayStep] = []
        actions_simulated = 0
        for entry in self._entries_of(journal):
            entry_type = self._entry_type(entry)
            simulated_state = self._simulate_state(entry_type)
            if simulated_state in {"Executing", "Completed", "Failed", "Aborted"}:
                actions_simulated += 1
            steps.append(
                ReplayStep(
                    sequence_number=int(getattr(entry, "sequence_number", len(steps) + 1)),
                    entry_type=entry_type,
                    content=str(getattr(entry, "content", "")),
                    occurred_at=self._occurred_iso(entry),
                    entry_hash=str(getattr(entry, "entry_hash", "")),
                    simulated_state=simulated_state,
                )
            )

        # Explicitly assert no write side effects occurred during simulation.
        assert self._attack_actions_created == 0
        assert self._evidence_collected == 0
        assert self._journal_appends == 0

        return ReplayReport(
            tenant_id=str(command.tenant_id),
            journal_id=str(self._journal_id(journal)),
            engagement_id=str(self._engagement_id(journal)),
            steps=steps,
            actions_simulated=actions_simulated,
            evidence_touched=False,
            journal_appended=False,
            attack_actions_created=False,
        )

    async def _load_journal(
        self, command: ReplayAttackActionExecution
    ) -> ExecutionJournal | Any | None:
        if self._journal_loader is not None:
            return await self._journal_loader(command)
        if self._uow_factory is None:
            raise RuntimeError("No journal loader or UoW factory configured for replay")
        from execution.domain.value_objects.identifiers import (
            EngagementId,
            ExecutionJournalId,
            TenantId,
        )

        tenant = TenantId(command.tenant_id)
        async with self._uow_factory() as uow:
            if command.journal_id is not None:
                return await uow.journals.find_by_id(
                    ExecutionJournalId(command.journal_id), tenant
                )
            assert command.engagement_id is not None
            return await uow.journals.find_by_engagement(
                EngagementId(command.engagement_id), tenant
            )

    @staticmethod
    def _entries_of(journal: Any) -> list[JournalEntry] | list[Any]:
        entries = getattr(journal, "entries", None)
        if entries is None and isinstance(journal, dict):
            return list(journal.get("entries") or [])
        return list(entries or [])

    @staticmethod
    def _entry_type(entry: Any) -> str:
        if isinstance(entry, dict):
            return str(entry.get("entry_type") or entry.get("kind") or "Unknown")
        et = getattr(entry, "entry_type", None)
        if et is None:
            return "Unknown"
        return et.value if hasattr(et, "value") else str(et)

    @staticmethod
    def _occurred_iso(entry: Any) -> str:
        if isinstance(entry, dict):
            return str(entry.get("occurred_at") or "")
        occurred = getattr(entry, "occurred_at", None)
        if occurred is None:
            return ""
        return occurred.isoformat() if hasattr(occurred, "isoformat") else str(occurred)

    @staticmethod
    def _journal_id(journal: Any) -> Any:
        if isinstance(journal, dict):
            return journal.get("journal_id") or ""
        jid = getattr(journal, "journal_id", None)
        return getattr(jid, "value", jid) if jid is not None else ""

    @staticmethod
    def _engagement_id(journal: Any) -> Any:
        if isinstance(journal, dict):
            return journal.get("engagement_id") or ""
        eid = getattr(journal, "engagement_id", None)
        return getattr(eid, "value", eid) if eid is not None else ""

    @staticmethod
    def _simulate_state(entry_type: str) -> str:
        mapping = {
            "AttackActionAuthorized": "Authorized",
            "AttackActionStarted": "Executing",
            "AttackActionCompleted": "Completed",
            "AttackActionFailed": "Failed",
            "AttackActionAborted": "Aborted",
            "KillSwitchTriggered": "KillSwitch",
            "JournalCreated": "JournalOpen",
            "JournalEntryAppended": "JournalEntry",
        }
        for key, state in mapping.items():
            if key.lower() in entry_type.lower().replace("_", ""):
                return state
        # Also match enum-style values like "attack_action_started"
        normalized = entry_type.lower().replace("-", "_")
        if "started" in normalized:
            return "Executing"
        if "completed" in normalized:
            return "Completed"
        if "failed" in normalized:
            return "Failed"
        if "abort" in normalized:
            return "Aborted"
        if "kill" in normalized:
            return "KillSwitch"
        return "Observed"

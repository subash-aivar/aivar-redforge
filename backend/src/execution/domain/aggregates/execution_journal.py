"""ExecutionJournal aggregate — append-only hash-chained audit log per engagement."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from execution.domain.entities.journal_entry import JournalEntry
from execution.domain.events.safety_events import (
    JournalChainIntegrityFailed,
    JournalCreated,
    JournalEntryAppended,
)
from execution.domain.exceptions.domain_exceptions import TenantMismatch
from execution.domain.value_objects.enums import ChainIntegrityStatus, JournalEntryType
from execution.domain.value_objects.execution_vos import ChainIntegrityReport
from execution.domain.value_objects.identifiers import ExecutionJournalId, JournalEntryId

if TYPE_CHECKING:
    from datetime import datetime

    from execution.domain.events.base import BaseDomainEvent
    from execution.domain.value_objects.identifiers import (
        EngagementId,
        OperatorId,
        TenantId,
    )

_GENESIS_HASH = "0" * 64


class ExecutionJournal:
    """One journal per engagement; entries never updated or deleted."""

    __slots__ = (
        "_pending_events",
        "_version",
        "created_at",
        "engagement_id",
        "entries",
        "journal_id",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        journal_id: ExecutionJournalId,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        created_at: datetime,
        updated_at: datetime,
        version: int,
        entries: list[JournalEntry] | None = None,
    ) -> None:
        self.journal_id = journal_id
        self.tenant_id = tenant_id
        self.engagement_id = engagement_id
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self.entries: list[JournalEntry] = list(entries or [])
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> ExecutionJournalId:
        return self.journal_id

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        now: datetime,
    ) -> ExecutionJournal:
        journal = cls(
            journal_id=ExecutionJournalId.generate(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            created_at=now,
            updated_at=now,
            version=0,
        )
        journal._emit(
            JournalCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(journal.journal_id),
                aggregate_type="ExecutionJournal",
                engagement_id=str(engagement_id),
            )
        )
        return journal

    def append_entry(
        self,
        tenant_id: TenantId,
        entry_type: JournalEntryType,
        content: str,
        now: datetime,
        *,
        attribution: OperatorId | None = None,
        system_attribution: str | None = None,
        corrects_ref: JournalEntryId | None = None,
    ) -> JournalEntry:
        self._assert_tenant(tenant_id)
        previous_hash = (
            self.entries[-1].entry_hash if self.entries else _GENESIS_HASH
        )
        sequence = len(self.entries) + 1
        entry_id = JournalEntryId.generate()
        provisional = JournalEntry(
            entry_id=entry_id,
            entry_type=entry_type,
            sequence_number=sequence,
            entry_hash="",
            previous_entry_hash=previous_hash,
            content=content,
            attribution=attribution,
            system_attribution=system_attribution,
            occurred_at=now,
            corrects_ref=corrects_ref,
        )
        entry_hash = JournalEntry.compute_entry_hash(
            previous_hash, provisional.content_for_hash()
        )
        entry = JournalEntry(
            entry_id=entry_id,
            entry_type=entry_type,
            sequence_number=sequence,
            entry_hash=entry_hash,
            previous_entry_hash=previous_hash,
            content=content,
            attribution=attribution,
            system_attribution=system_attribution,
            occurred_at=now,
            corrects_ref=corrects_ref,
        )
        self.entries.append(entry)
        self._mutate(now)
        self._emit(
            JournalEntryAppended(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.journal_id),
                aggregate_type="ExecutionJournal",
                journal_id=str(self.journal_id),
                entry_id=str(entry_id),
                entry_type=entry_type.value,
                sequence_number=sequence,
                entry_hash=entry_hash,
            )
        )
        return entry

    def verify_chain_integrity(self, now: datetime) -> ChainIntegrityReport:
        previous = _GENESIS_HASH
        for entry in self.entries:
            expected_prev = previous
            if entry.previous_entry_hash != expected_prev:
                report = ChainIntegrityReport(
                    status=ChainIntegrityStatus.BROKEN,
                    journal_id=str(self.journal_id),
                    entry_count=len(self.entries),
                    broken_at_sequence=entry.sequence_number,
                    detail=(
                        f"previous_entry_hash mismatch at sequence "
                        f"{entry.sequence_number}"
                    ),
                )
                self._emit_integrity_failed(report, now)
                return report
            expected_hash = JournalEntry.compute_entry_hash(
                entry.previous_entry_hash, entry.content_for_hash()
            )
            if entry.entry_hash != expected_hash:
                report = ChainIntegrityReport(
                    status=ChainIntegrityStatus.BROKEN,
                    journal_id=str(self.journal_id),
                    entry_count=len(self.entries),
                    broken_at_sequence=entry.sequence_number,
                    detail=f"entry_hash mismatch at sequence {entry.sequence_number}",
                )
                self._emit_integrity_failed(report, now)
                return report
            if entry.sequence_number != (
                self.entries.index(entry) + 1
            ):
                report = ChainIntegrityReport(
                    status=ChainIntegrityStatus.BROKEN,
                    journal_id=str(self.journal_id),
                    entry_count=len(self.entries),
                    broken_at_sequence=entry.sequence_number,
                    detail=f"sequence gap/disorder at {entry.sequence_number}",
                )
                self._emit_integrity_failed(report, now)
                return report
            previous = entry.entry_hash
        return ChainIntegrityReport(
            status=ChainIntegrityStatus.VERIFIED,
            journal_id=str(self.journal_id),
            entry_count=len(self.entries),
        )

    def _emit_integrity_failed(self, report: ChainIntegrityReport, now: datetime) -> None:
        self._emit(
            JournalChainIntegrityFailed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.journal_id),
                aggregate_type="ExecutionJournal",
                journal_id=str(self.journal_id),
                engagement_id=str(self.engagement_id),
                broken_at_sequence=report.broken_at_sequence,
                detail=report.detail,
            )
        )

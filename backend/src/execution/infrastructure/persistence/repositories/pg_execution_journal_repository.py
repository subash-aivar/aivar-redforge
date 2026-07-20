"""PgExecutionJournalRepository — append-only journal with advisory lock."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, select, text, update

from execution.domain.aggregates.execution_journal import ExecutionJournal
from execution.domain.entities.journal_entry import JournalEntry
from execution.domain.exceptions.domain_exceptions import OptimisticLockConflict
from execution.domain.repositories.i_repositories import IExecutionJournalRepository
from execution.domain.value_objects.enums import JournalEntryType
from execution.domain.value_objects.identifiers import (
    EngagementId,
    ExecutionJournalId,
    JournalEntryId,
    OperatorId,
    TenantId,
)
from execution.infrastructure.persistence.models.execution_models import (
    ExecutionJournalModel,
    JournalEntryModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgExecutionJournalRepository(IExecutionJournalRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, journal: ExecutionJournal) -> None:
        # Advisory lock serializes hash-chain appends for this journal (Hardening §2).
        lock_key = journal.journal_id.value.int & 0x7FFFFFFFFFFFFFFF
        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key}
        )

        existing = await self._session.get(
            ExecutionJournalModel, journal.journal_id.value
        )
        if existing is None:
            model = ExecutionJournalModel(
                id=journal.journal_id.value,
                tenant_id=journal.tenant_id.value,
                engagement_id=journal.engagement_id.value,
                created_at=journal.created_at,
                updated_at=journal.updated_at,
                row_version=1,
            )
            self._session.add(model)
            journal._version = 1
        else:
            if existing.tenant_id != journal.tenant_id.value:
                raise OptimisticLockConflict(str(journal.journal_id), journal.version, -1)
            expected = journal.version
            stmt = (
                update(ExecutionJournalModel)
                .where(
                    ExecutionJournalModel.id == journal.journal_id.value,
                    ExecutionJournalModel.row_version == expected,
                )
                .values(updated_at=journal.updated_at, row_version=expected + 1)
            )
            result = await self._session.execute(stmt)
            if result.rowcount == 0:  # type: ignore[attr-defined]
                raise OptimisticLockConflict(
                    str(journal.journal_id), expected, existing.row_version
                )
            journal._version = expected + 1
            await self._session.execute(
                delete(JournalEntryModel).where(
                    JournalEntryModel.journal_id == journal.journal_id.value
                )
            )

        for entry in journal.entries:
            self._session.add(
                JournalEntryModel(
                    id=entry.entry_id.value,
                    tenant_id=journal.tenant_id.value,
                    journal_id=journal.journal_id.value,
                    entry_type=entry.entry_type.value,
                    sequence_number=entry.sequence_number,
                    entry_hash=entry.entry_hash,
                    previous_entry_hash=entry.previous_entry_hash,
                    content=entry.content,
                    attribution_operator_id=(
                        entry.attribution.value if entry.attribution else None
                    ),
                    system_attribution=entry.system_attribution,
                    corrects_ref=entry.corrects_ref.value if entry.corrects_ref else None,
                    occurred_at=entry.occurred_at,
                )
            )

    async def find_by_id(
        self, journal_id: ExecutionJournalId, tenant_id: TenantId
    ) -> ExecutionJournal | None:
        model = await self._session.get(ExecutionJournalModel, journal_id.value)
        if model is None or model.tenant_id != tenant_id.value:
            return None
        return await self._load(model)

    async def find_by_engagement(
        self, engagement_id: EngagementId, tenant_id: TenantId
    ) -> ExecutionJournal | None:
        stmt = select(ExecutionJournalModel).where(
            ExecutionJournalModel.tenant_id == tenant_id.value,
            ExecutionJournalModel.engagement_id == engagement_id.value,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return await self._load(model)

    async def _load(self, model: ExecutionJournalModel) -> ExecutionJournal:
        stmt = (
            select(JournalEntryModel)
            .where(JournalEntryModel.journal_id == model.id)
            .order_by(JournalEntryModel.sequence_number)
        )
        result = await self._session.execute(stmt)
        entries = [
            JournalEntry(
                entry_id=JournalEntryId(row.id),
                entry_type=JournalEntryType(row.entry_type),
                sequence_number=row.sequence_number,
                entry_hash=row.entry_hash,
                previous_entry_hash=row.previous_entry_hash,
                content=row.content,
                attribution=(
                    OperatorId(row.attribution_operator_id)
                    if row.attribution_operator_id
                    else None
                ),
                system_attribution=row.system_attribution,
                occurred_at=row.occurred_at,
                corrects_ref=(
                    JournalEntryId(row.corrects_ref) if row.corrects_ref else None
                ),
            )
            for row in result.scalars().all()
        ]
        return ExecutionJournal(
            journal_id=ExecutionJournalId(model.id),
            tenant_id=TenantId(model.tenant_id),
            engagement_id=EngagementId(model.engagement_id),
            created_at=model.created_at,
            updated_at=model.updated_at,
            version=model.row_version,
            entries=entries,
        )

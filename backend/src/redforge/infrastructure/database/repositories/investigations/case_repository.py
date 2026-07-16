"""Investigation case repository — M21.

Concurrency patterns (matching M19/M20):
  - Advisory lock on (org_id, correlation_key) hash before case creation
  - SAVEPOINT + refetch on IntegrityError for concurrent race
  - Optimistic version check for lifecycle transitions
  - ON CONFLICT DO NOTHING for idempotent evidence links
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import CursorResult, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from ulid import ULID

from redforge.infrastructure.database.models.investigation import (
    CorrelationCursorModel,
    InvestigationEventModel,
    InvestigationEvidenceLinkModel,
    InvestigationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyInvestigationRepository:
    """PostgreSQL-backed investigation case repository.

    Provides race-safe creation using the advisory-lock +
    partial-unique-index pattern from M19/M20.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_or_get_active(
        self,
        organization_id: str,
        correlation_key: str,
        title: str,
        summary: str,
        status: str,
        severity: str,
        confidence: str,
        source_domains: list[str],
        involved_entities: list[dict[str, str]],
        first_observed_at: datetime,
        opened_at: datetime,
        now: datetime | None = None,
    ) -> tuple[InvestigationModel, bool]:
        """Race-safe: get existing active case or create new one.

        Uses pg_advisory_xact_lock on (org_id, correlation_key) hash,
        then SAVEPOINT + IntegrityError refetch — identical to the
        DDoS/behavior pattern. Returns (model, created).
        """
        now = now or datetime.now(UTC)
        lock_hash = hash((organization_id, correlation_key)) & 0x7FFFFFFFFFFFFFFF

        await self._session.execute(
            text("SELECT pg_advisory_xact_lock(:h)"), {"h": lock_hash}
        )

        # Check for existing active case
        result = await self._session.execute(
            select(InvestigationModel).where(
                InvestigationModel.organization_id == organization_id,
                InvestigationModel.correlation_key == correlation_key,
                InvestigationModel.status != "RESOLVED",
            )
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing, False

        # Create new case
        case_id = str(ULID())
        model = InvestigationModel(
            id=case_id,
            organization_id=organization_id,
            title=title,
            summary=summary,
            status=status,
            severity=severity,
            confidence=confidence,
            correlation_key=correlation_key,
            source_domains=source_domains,
            involved_entities=involved_entities,
            evidence_count=0,
            first_observed_at=first_observed_at,
            last_observed_at=first_observed_at,
            opened_at=opened_at,
            acknowledged_at=None,
            investigating_at=None,
            resolved_at=None,
            resolution_reason=None,
            resolution_notes="",
            version=0,
            created_at=now,
            updated_at=now,
        )

        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model, True
        except IntegrityError:
            # Concurrent worker created the same correlation_key first.
            result2 = await self._session.execute(
                select(InvestigationModel).where(
                    InvestigationModel.organization_id == organization_id,
                    InvestigationModel.correlation_key == correlation_key,
                    InvestigationModel.status != "RESOLVED",
                )
            )
            winner = result2.scalar_one_or_none()
            if winner is None:
                raise  # genuinely unexpected
            return winner, False

    async def get(
        self, organization_id: str, case_id: str
    ) -> InvestigationModel | None:
        result = await self._session.execute(
            select(InvestigationModel).where(
                InvestigationModel.id == case_id,
                InvestigationModel.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_by_correlation_key(
        self, organization_id: str, correlation_key: str
    ) -> InvestigationModel | None:
        """Return active (non-RESOLVED) case for a correlation key."""
        result = await self._session.execute(
            select(InvestigationModel).where(
                InvestigationModel.organization_id == organization_id,
                InvestigationModel.correlation_key == correlation_key,
                InvestigationModel.status != "RESOLVED",
            )
        )
        return result.scalar_one_or_none()

    async def get_resolved_by_correlation_key(
        self, organization_id: str, correlation_key: str
    ) -> InvestigationModel | None:
        """Return the most recently resolved case for a correlation key."""
        result = await self._session.execute(
            select(InvestigationModel)
            .where(
                InvestigationModel.organization_id == organization_id,
                InvestigationModel.correlation_key == correlation_key,
                InvestigationModel.status == "RESOLVED",
            )
            .order_by(InvestigationModel.resolved_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def update_status(
        self,
        organization_id: str,
        case_id: str,
        new_status: str,
        current_version: int,
        updates: dict[str, Any] | None = None,
    ) -> bool:
        """CAS update on version. Returns True if 1 row was updated."""
        values: dict[str, Any] = {
            "status": new_status,
            "version": current_version + 1,
            "updated_at": datetime.now(UTC),
        }
        if updates:
            values.update(updates)
        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                update(InvestigationModel)
                .where(
                    InvestigationModel.id == case_id,
                    InvestigationModel.organization_id == organization_id,
                    InvestigationModel.version == current_version,
                )
                .values(**values)
            ),
        )
        return result.rowcount == 1

    async def update_evidence_metrics(
        self,
        organization_id: str,
        case_id: str,
        new_severity: str,
        new_confidence: str,
        new_last_observed_at: datetime,
        new_source_domains: list[str],
        new_entities: list[dict[str, str]],
    ) -> None:
        """Update severity, confidence, timestamps, domains, entities."""
        await self._session.execute(
            update(InvestigationModel)
            .where(
                InvestigationModel.id == case_id,
                InvestigationModel.organization_id == organization_id,
            )
            .values(
                severity=new_severity,
                confidence=new_confidence,
                last_observed_at=new_last_observed_at,
                source_domains=new_source_domains,
                involved_entities=new_entities,
                evidence_count=InvestigationModel.evidence_count + 1,
                updated_at=datetime.now(UTC),
            )
        )

    async def reopen(
        self,
        organization_id: str,
        case_id: str,
        current_version: int,
        now: datetime | None = None,
    ) -> bool:
        """Reopen a RESOLVED case (CAS on version)."""
        now = now or datetime.now(UTC)
        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                update(InvestigationModel)
                .where(
                    InvestigationModel.id == case_id,
                    InvestigationModel.organization_id == organization_id,
                    InvestigationModel.version == current_version,
                    InvestigationModel.status == "RESOLVED",
                )
                .values(
                    status="OPEN",
                    resolved_at=None,
                    resolution_reason=None,
                    resolution_notes="",
                    version=current_version + 1,
                    updated_at=now,
                )
            ),
        )
        return result.rowcount == 1

    async def list_cases(
        self,
        organization_id: str,
        *,
        status: str | None = None,
        severity: str | None = None,
        source_domain: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[InvestigationModel]:
        q = select(InvestigationModel).where(
            InvestigationModel.organization_id == organization_id
        )
        if status:
            q = q.where(InvestigationModel.status == status)
        if severity:
            q = q.where(InvestigationModel.severity == severity)
        if since:
            q = q.where(InvestigationModel.opened_at >= since)
        q = q.order_by(InvestigationModel.opened_at.desc()).limit(limit).offset(offset)
        result = await self._session.execute(q)
        rows = list(result.scalars().all())
        if source_domain:
            # Filter in Python — JSON array containment check
            rows = [r for r in rows if source_domain in (r.source_domains or [])]
        return rows

    async def count_by_status(
        self, organization_id: str
    ) -> dict[str, int]:
        result = await self._session.execute(
            select(InvestigationModel.status, func.count(InvestigationModel.id))
            .where(InvestigationModel.organization_id == organization_id)
            .group_by(InvestigationModel.status)
        )
        return {row[0]: row[1] for row in result.all()}

    async def count_multi_domain(self, organization_id: str) -> int:
        """Count cases with 2+ source domains (multi-domain correlation)."""
        result = await self._session.execute(
            select(func.count(InvestigationModel.id))
            .where(
                InvestigationModel.organization_id == organization_id,
                InvestigationModel.status != "RESOLVED",
            )
        )
        result.scalar_one_or_none() or 0
        # Filter in Python for JSON array length
        all_active = await self._session.execute(
            select(InvestigationModel.source_domains)
            .where(
                InvestigationModel.organization_id == organization_id,
                InvestigationModel.status != "RESOLVED",
            )
        )
        return sum(
            1 for (domains,) in all_active.all()
            if domains and len(domains) >= 2
        )


class SqlAlchemyEvidenceLinkRepository:
    """Idempotent evidence link repository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_link_if_absent(
        self,
        organization_id: str,
        case_id: str,
        source_domain: str,
        source_entity_type: str,
        source_entity_id: str,
        event_type: str,
        severity: str,
        observed_at: datetime,
        evidence_snapshot: dict[str, Any],
        correlation_reason: str,
        relationship_type: str,
        observability: str,
        dedup_key: str,
        now: datetime | None = None,
    ) -> tuple[InvestigationEvidenceLinkModel, bool]:
        """Insert evidence link or skip on duplicate dedup_key.

        Returns (model, created=True) on insert, (existing, False) on duplicate.
        """
        now = now or datetime.now(UTC)
        link_id = str(ULID())

        stmt = (
            pg_insert(InvestigationEvidenceLinkModel)
            .values(
                id=link_id,
                organization_id=organization_id,
                case_id=case_id,
                source_domain=source_domain,
                source_entity_type=source_entity_type,
                source_entity_id=source_entity_id,
                event_type=event_type,
                severity=severity,
                observed_at=observed_at,
                evidence_snapshot=evidence_snapshot,
                correlation_reason=correlation_reason,
                relationship_type=relationship_type,
                observability=observability,
                dedup_key=dedup_key,
                created_at=now,
            )
            .on_conflict_do_nothing(
                constraint="ux_iel_org_case_dedup"
            )
        )
        cursor_result = cast("CursorResult[Any]", await self._session.execute(stmt))
        created = cursor_result.rowcount == 1

        if not created:
            # Return the existing row
            existing_result = await self._session.execute(
                select(InvestigationEvidenceLinkModel).where(
                    InvestigationEvidenceLinkModel.organization_id == organization_id,
                    InvestigationEvidenceLinkModel.case_id == case_id,
                    InvestigationEvidenceLinkModel.dedup_key == dedup_key,
                )
            )
            existing = existing_result.scalar_one()
            return existing, False

        # Fetch the newly inserted row
        new_result = await self._session.execute(
            select(InvestigationEvidenceLinkModel).where(
                InvestigationEvidenceLinkModel.id == link_id
            )
        )
        return new_result.scalar_one(), True

    async def list_for_case(
        self,
        organization_id: str,
        case_id: str,
        source_domain: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[InvestigationEvidenceLinkModel]:
        q = select(InvestigationEvidenceLinkModel).where(
            InvestigationEvidenceLinkModel.organization_id == organization_id,
            InvestigationEvidenceLinkModel.case_id == case_id,
        )
        if source_domain:
            q = q.where(
                InvestigationEvidenceLinkModel.source_domain == source_domain
            )
        q = q.order_by(InvestigationEvidenceLinkModel.observed_at.asc()).limit(limit).offset(offset)
        result = await self._session.execute(q)
        return list(result.scalars().all())

    async def count_domains(
        self, organization_id: str, case_id: str
    ) -> int:
        result = await self._session.execute(
            select(
                func.count(
                    func.distinct(InvestigationEvidenceLinkModel.source_domain)
                )
            ).where(
                InvestigationEvidenceLinkModel.organization_id == organization_id,
                InvestigationEvidenceLinkModel.case_id == case_id,
            )
        )
        return result.scalar_one_or_none() or 0


class SqlAlchemyInvestigationEventRepository:
    """Append-only investigation timeline event repository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append_event(
        self,
        organization_id: str,
        case_id: str,
        event_type: str,
        event_id: str,
        detail: dict[str, Any],
        actor_user_id: str | None,
        occurred_at: datetime,
    ) -> None:
        """Append event; idempotent on event_id (unique constraint)."""
        stmt = (
            pg_insert(InvestigationEventModel)
            .values(
                id=str(ULID()),
                event_id=event_id,
                organization_id=organization_id,
                case_id=case_id,
                event_type=event_type,
                detail=detail,
                actor_user_id=actor_user_id,
                occurred_at=occurred_at,
            )
            .on_conflict_do_nothing(constraint="ux_iev_event_id")
        )
        await self._session.execute(stmt)

    async def list_events(
        self,
        organization_id: str,
        case_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> list[InvestigationEventModel]:
        result = await self._session.execute(
            select(InvestigationEventModel)
            .where(
                InvestigationEventModel.organization_id == organization_id,
                InvestigationEventModel.case_id == case_id,
            )
            .order_by(InvestigationEventModel.occurred_at.asc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def list_opened_events_since(
        self,
        organization_id: str,
        since: datetime,
        limit: int,
    ) -> list[InvestigationEventModel]:
        """Stream integration: CASE_OPENED events for operational feed."""
        result = await self._session.execute(
            select(InvestigationEventModel)
            .where(
                InvestigationEventModel.organization_id == organization_id,
                InvestigationEventModel.event_type == "CASE_OPENED",
                InvestigationEventModel.occurred_at > since,
            )
            .order_by(InvestigationEventModel.occurred_at.asc())
            .limit(limit)
        )
        return list(result.scalars().all())


class SqlAlchemyCorrelationCursorRepository:
    """Per-source-domain worker cursor persistence."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_cursor(
        self, source_domain: str
    ) -> tuple[datetime | None, str | None]:
        """Return (last_processed_at, last_processed_id) or (None, None)."""
        result = await self._session.execute(
            select(CorrelationCursorModel).where(
                CorrelationCursorModel.source_domain == source_domain
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None, None
        return row.last_processed_at, row.last_processed_id

    async def set_cursor(
        self,
        source_domain: str,
        last_processed_at: datetime,
        last_processed_id: str,
    ) -> None:
        """Upsert the processing cursor for a source domain."""
        now = datetime.now(UTC)
        stmt = (
            pg_insert(CorrelationCursorModel)
            .values(
                id=str(ULID()),
                source_domain=source_domain,
                last_processed_at=last_processed_at,
                last_processed_id=last_processed_id,
                updated_at=now,
            )
            .on_conflict_do_update(
                constraint="ux_icc_source_domain",
                set_={
                    "last_processed_at": last_processed_at,
                    "last_processed_id": last_processed_id,
                    "updated_at": now,
                },
            )
        )
        await self._session.execute(stmt)

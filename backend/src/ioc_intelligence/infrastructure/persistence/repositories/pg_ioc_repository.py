"""PgIocRepository — SQLAlchemy implementation of `IIocRepository`
(M51.2 Phase A3), mirroring `threat_actor_intel.infrastructure.
persistence.repositories.pg_threat_actor_repository`'s translation
shape (no business logic, no authorization) plus `operation`'s
real optimistic-concurrency enforcement (`pg_operation_repository.
save()`'s compare-and-swap `UPDATE ... WHERE row_version = expected
RETURNING row_version` pattern) — `ThreatActorModel` declares
`row_version` but does not yet enforce it; this repository does.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (with `scope=None` meaning "global rows only",
via `IocModel.tenant_id.is_(None)`), so a row belonging to a different
scope is indistinguishable from "does not exist" — this repository
never returns a global row for a tenant-scoped query, or a tenant row
for a global query, and never has an "accidental unbounded" query path
that could leak across scopes.

Source attributions and evidence citations are wholesale-replaced on
every `save()` (identity-less child rows, same shape as `ThreatActor`'s
aliases/techniques/indicators) — the repository does not deduplicate
or merge anything; the `IOC` aggregate itself is the sole authority on
what its own collections contain by the time `save()` is called."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import delete, exists, func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from ioc_intelligence.application.ports.i_ioc_repository import IIocRepository
from ioc_intelligence.application.queries.ioc_queries import (
    IocSortField,
    SortDirection,
    ValidityFilter,
)
from ioc_intelligence.domain.aggregates.ioc import IOC
from ioc_intelligence.domain.value_objects.enums import (
    EpistemicState,
    IocLifecycle,
    IocType,
    SourceConfidence,
)
from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
from ioc_intelligence.domain.value_objects.identifiers import IocId, TenantId
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution
from ioc_intelligence.domain.value_objects.validity import ValidityWindow
from ioc_intelligence.infrastructure.persistence.exceptions import (
    IocIntelIntegrityError,
    OptimisticLockConflictError,
)
from ioc_intelligence.infrastructure.persistence.models.ioc_models import (
    IocEvidenceCitationModel,
    IocModel,
    IocSourceAttributionModel,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement

# Whitelist mapping every allowed `IocSortField` to a real, trusted
# SQLAlchemy column — the ONLY way a caller-supplied sort key ever
# reaches a query. No raw string is ever interpolated into `ORDER BY`.
_SORT_COLUMNS: dict[IocSortField, Any] = {
    IocSortField.CREATED_AT: IocModel.created_at,
    IocSortField.UPDATED_AT: IocModel.updated_at,
    IocSortField.VALID_UNTIL: IocModel.valid_until,
    IocSortField.IOC_TYPE: IocModel.ioc_type,
    IocSortField.LIFECYCLE: IocModel.lifecycle,
    IocSortField.EPISTEMIC_STATE: IocModel.epistemic_state,
}

# `%`/`_` are ILIKE wildcards — escape any the caller typed literally so
# a search for e.g. "50%" or "a_b" matches those literal characters
# instead of behaving as a wildcard the caller didn't intend.
_ILIKE_ESCAPE_MAP = str.maketrans({"%": r"\%", "_": r"\_", "\\": "\\\\"})


def _escape_ilike(value: str) -> str:
    return value.translate(_ILIKE_ESCAPE_MAP)


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return IocModel.tenant_id.is_(None)
    return IocModel.tenant_id == tenant_uuid


def _row_to_ioc(row: IocModel) -> IOC:
    ioc_type = IocType(row.ioc_type)
    canonical_key = IndicatorCanonicalKey(f"{row.ioc_type}:{row.normalized_value}")
    ioc = IOC(
        ioc_id=IocId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        ioc_type=ioc_type,
        canonical_key=canonical_key,
        validity_window=ValidityWindow(valid_from=row.valid_from, valid_until=row.valid_until),
        lifecycle=IocLifecycle(row.lifecycle),
        epistemic_state=EpistemicState(row.epistemic_state),
        created_at=row.created_at,
        updated_at=row.updated_at,
        source_attributions=tuple(
            SourceAttribution(
                source_system=a.source_system,
                external_id=a.external_id,
                content_hash=a.content_hash,
                observed_at=a.observed_at,
                weight_applied=a.weight_applied,
                confidence=SourceConfidence(a.confidence),
                metadata=dict(a.attribution_metadata),
            )
            for a in row.source_attributions
        ),
        evidence_citations=tuple(EvidenceCitation(c.citation) for c in row.evidence_citations),
        row_version=row.row_version,
    )
    return ioc


class PgIocRepository(IIocRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, ioc: IOC) -> None:
        # Transaction ownership belongs to the Unit of Work, not this
        # repository — on error we translate the exception and let it
        # propagate; the caller's `IUnitOfWork.__aexit__` is what
        # performs the actual rollback.
        try:
            await self._save(ioc)
        except IntegrityError as exc:
            raise IocIntelIntegrityError("save IOC", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            raise IocIntelIntegrityError("save IOC", str(exc)) from exc

    async def _save(self, ioc: IOC) -> None:
        ioc_uuid = ioc.ioc_id.value
        tenant_uuid = _tenant_uuid(ioc.tenant_id)

        row = await self._session.get(IocModel, ioc_uuid)
        if row is None:
            row = IocModel(
                id=ioc_uuid,
                tenant_id=tenant_uuid,
                ioc_type=ioc.ioc_type.value,
                normalized_value=ioc.canonical_key.normalized_value,
                lifecycle=ioc.lifecycle.value,
                epistemic_state=ioc.epistemic_state.value,
                valid_from=ioc.validity_window.valid_from,
                valid_until=ioc.validity_window.valid_until,
                created_at=ioc.created_at,
                updated_at=ioc.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(ioc, ioc_uuid)
            await self._session.flush()
            ioc.row_version = 1
            return

        expected = ioc.row_version
        result = await self._session.execute(
            update(IocModel)
            .where(IocModel.id == ioc_uuid, IocModel.row_version == expected)
            .values(
                tenant_id=tenant_uuid,
                lifecycle=ioc.lifecycle.value,
                epistemic_state=ioc.epistemic_state.value,
                valid_from=ioc.validity_window.valid_from,
                valid_until=ioc.validity_window.valid_until,
                updated_at=ioc.updated_at,
                row_version=expected + 1,
            )
            .returning(IocModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(IocModel, ioc_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(ioc.ioc_id), expected, actual)

        await self._replace_children(ioc, ioc_uuid)
        await self._session.flush()
        ioc.row_version = int(new_version)

    async def _replace_children(self, ioc: IOC, ioc_uuid: UUID) -> None:
        await self._session.execute(
            delete(IocSourceAttributionModel).where(IocSourceAttributionModel.ioc_id == ioc_uuid)
        )
        for attribution in ioc.source_attributions:
            self._session.add(
                IocSourceAttributionModel(
                    id=uuid4(),
                    ioc_id=ioc_uuid,
                    source_system=attribution.source_system,
                    external_id=attribution.external_id,
                    content_hash=attribution.content_hash,
                    observed_at=attribution.observed_at,
                    weight_applied=attribution.weight_applied,
                    confidence=attribution.confidence.value,
                    attribution_metadata=dict(attribution.metadata),
                )
            )

        await self._session.execute(
            delete(IocEvidenceCitationModel).where(IocEvidenceCitationModel.ioc_id == ioc_uuid)
        )
        for citation in ioc.evidence_citations:
            self._session.add(
                IocEvidenceCitationModel(id=uuid4(), ioc_id=ioc_uuid, citation=str(citation))
            )

    async def get(self, tenant_id: TenantId | None, ioc_id: IocId) -> IOC | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(IocModel).where(IocModel.id == ioc_id.value)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_ioc(row)

    async def get_any(self, ioc_id: IocId) -> IOC | None:
        row = await self._session.get(IocModel, ioc_id.value)
        if row is None:
            return None
        return _row_to_ioc(row)

    async def get_by_canonical_key(
        self, tenant_id: TenantId | None, canonical_key: IndicatorCanonicalKey
    ) -> IOC | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(IocModel).where(
            IocModel.ioc_type == canonical_key.ioc_type.value,
            IocModel.normalized_value == canonical_key.normalized_value,
        )
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_ioc(row)

    async def list_and_count(
        self,
        tenant_id: TenantId | None,
        *,
        lifecycle: IocLifecycle | None = None,
        epistemic_state: EpistemicState | None = None,
        ioc_type: IocType | None = None,
        search: str | None = None,
        confidence: SourceConfidence | None = None,
        source_system: str | None = None,
        validity: ValidityFilter | None = None,
        sort_by: IocSortField = IocSortField.CREATED_AT,
        sort_dir: SortDirection = SortDirection.DESC,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[IOC], int]:
        tenant_uuid = _tenant_uuid(tenant_id)
        base = select(IocModel).where(_tenant_filter(tenant_uuid))
        if lifecycle is not None:
            base = base.where(IocModel.lifecycle == lifecycle.value)
        if epistemic_state is not None:
            base = base.where(IocModel.epistemic_state == epistemic_state.value)
        if ioc_type is not None:
            base = base.where(IocModel.ioc_type == ioc_type.value)
        if search:
            pattern = f"%{_escape_ilike(search)}%"
            base = base.where(IocModel.normalized_value.ilike(pattern, escape="\\"))
        if validity is ValidityFilter.VALID:
            base = base.where(
                (IocModel.valid_until.is_(None)) | (IocModel.valid_until > func.now())
            )
        elif validity is ValidityFilter.LAPSED:
            base = base.where(IocModel.valid_until.is_not(None), IocModel.valid_until <= func.now())
        if confidence is not None:
            base = base.where(
                exists(
                    select(1).where(
                        IocSourceAttributionModel.ioc_id == IocModel.id,
                        IocSourceAttributionModel.confidence == confidence.value,
                    )
                )
            )
        if source_system:
            base = base.where(
                exists(
                    select(1).where(
                        IocSourceAttributionModel.ioc_id == IocModel.id,
                        IocSourceAttributionModel.source_system == source_system,
                    )
                )
            )

        # Total across the ENTIRE filtered dataset, computed from the
        # same filtered query before limit/offset — never len(page).
        count_stmt = select(func.count()).select_from(base.subquery())
        total = (await self._session.execute(count_stmt)).scalar_one()

        primary_column = _SORT_COLUMNS[sort_by]
        order = (
            (primary_column.desc(), IocModel.id.desc())
            if sort_dir is SortDirection.DESC
            else (primary_column.asc(), IocModel.id.asc())
        )
        # Stable ordering: `id` is always the final tiebreaker so
        # pagination is well-defined even when the primary sort column
        # has duplicate values across rows.
        stmt = base.order_by(*order).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_ioc(row) for row in rows], int(total)

    async def list_lapsed_active(self, now: datetime, limit: int = 200) -> Sequence[IOC]:
        stmt = (
            select(IocModel)
            .where(
                IocModel.lifecycle == IocLifecycle.ACTIVE.value,
                IocModel.valid_until.is_not(None),
                IocModel.valid_until < now,
            )
            .order_by(IocModel.valid_until.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_ioc(row) for row in rows]

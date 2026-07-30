"""Integration test asserting raw SQLAlchemy/DBAPI errors never leak
past the repository boundary — they are translated to
`RiskEngineIntegrityError`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from risk_engine.infrastructure.persistence.exceptions import RiskEngineIntegrityError
from risk_engine.infrastructure.persistence.models.risk_profile_model import (
    RiskProfileScoreHistoryModel,
)
from risk_engine.infrastructure.persistence.repositories.pg_risk_correlation_repository import (
    PgRiskCorrelationRepository,
)
from risk_engine.infrastructure.persistence.repositories.pg_risk_profile_repository import (
    PgEnterpriseRiskProfileRepository,
)
from tests.risk_engine.infrastructure.helpers import (
    make_composite_score,
    make_correlation_set,
    make_profile,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_score_history_unique_constraint_exists(re_session) -> None:
    """Sanity check that the DB-level guard `save()`'s translation
    relies on is actually in place: inserting two score-history rows
    for the same (profile_id, computed_at) raises at the DB layer."""
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    now = datetime.now(UTC)
    profile = make_profile(
        tenant_id, composite_score=make_composite_score(computed_at=now), now=now
    )
    await repo.save(profile)
    await re_session.commit()

    from uuid import uuid4

    from sqlalchemy.exc import IntegrityError

    re_session.add(
        RiskProfileScoreHistoryModel(
            id=uuid4(),
            profile_id=profile.profile_id.value,
            tenant_id=tenant_id.value.to_uuid(),
            value=1.0,
            weight_profile_id="dup",
            computed_at=now,
        )
    )
    with pytest.raises(IntegrityError):
        await re_session.flush()
    await re_session.rollback()


@pytest.mark.asyncio
async def test_save_translates_integrity_error_via_repository_guard(
    re_session, monkeypatch
) -> None:
    """Forces the repository's own IntegrityError branch by making the
    session's flush() raise a SQLAlchemy IntegrityError, and asserts
    the caller only ever sees `RiskEngineIntegrityError`."""
    from sqlalchemy.exc import IntegrityError

    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    profile = make_profile(tenant_id)

    def _boom(*args: object, **kwargs: object) -> None:
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(re_session, "flush", _boom)

    with pytest.raises(RiskEngineIntegrityError):
        await repo.save(profile)


@pytest.mark.asyncio
async def test_correlation_save_translates_integrity_error(re_session, monkeypatch) -> None:
    from sqlalchemy.exc import IntegrityError

    tenant_id = make_tenant_id()
    repo = PgRiskCorrelationRepository(re_session)
    correlation_set = make_correlation_set(tenant_id)

    def _boom(*args: object, **kwargs: object) -> None:
        raise IntegrityError("INSERT", {}, Exception("duplicate key"))

    monkeypatch.setattr(re_session, "flush", _boom)

    with pytest.raises(RiskEngineIntegrityError):
        await repo.save(correlation_set)

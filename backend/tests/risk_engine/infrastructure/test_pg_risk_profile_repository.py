"""Integration tests for PgEnterpriseRiskProfileRepository."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from risk_engine.domain.value_objects.enums import RiskDimension, RiskProfileStatus
from risk_engine.domain.value_objects.identifiers import RiskProfileId
from risk_engine.infrastructure.persistence.repositories.pg_risk_profile_repository import (
    PgEnterpriseRiskProfileRepository,
)
from tests.risk_engine.infrastructure.helpers import (
    make_composite_score,
    make_contribution,
    make_profile,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_cold_session_reload_exercises_selectin_relationship_loading(
    re_session_factory,
) -> None:
    """Regression test for the `MissingGreenlet` bug caught during the
    M48C async contract correction: a single shared `re_session` across
    save+get within one test can serve `row.contributions`/
    `row.score_history` straight out of SQLAlchemy's session-level
    identity map without ever issuing a real lazy/eager-load query —
    which would let a regression (e.g. someone removing
    `lazy="selectin"` from the ORM models) pass unnoticed. This test
    opens a brand-new `AsyncSession` with an empty identity map to
    `get()` a profile that a *different*, already-closed session
    wrote and committed, forcing a genuine cold DB read of the
    `contributions` and `score_history` relationships. Without
    `lazy="selectin"`, this raises `sqlalchemy.exc.MissingGreenlet`."""
    tenant_id = make_tenant_id()
    now = datetime.now(UTC)
    contributions = (
        make_contribution(tenant_id, dimension=RiskDimension.VULNERABILITY, normalized_value=7.0),
        make_contribution(tenant_id, dimension=RiskDimension.CLOUD, normalized_value=3.0),
    )
    composite = make_composite_score(value=5.0, computed_at=now)
    profile = make_profile(
        tenant_id, contributions=contributions, composite_score=composite, now=now
    )

    write_session = re_session_factory()
    try:
        write_repo = PgEnterpriseRiskProfileRepository(write_session)
        await write_repo.save(profile)
        await write_session.commit()
    finally:
        await write_session.close()

    # A fresh session/identity-map — nothing from the write above is
    # cached here. `get()` must issue real queries, including for the
    # two relationships, and must not raise MissingGreenlet.
    read_session = re_session_factory()
    try:
        read_repo = PgEnterpriseRiskProfileRepository(read_session)
        loaded = await read_repo.get(tenant_id, profile.profile_id)
        assert loaded is not None
        assert len(loaded.contributions) == 2
        dims = {c.dimension for c in loaded.contributions}
        assert dims == {RiskDimension.VULNERABILITY, RiskDimension.CLOUD}
        assert loaded.composite_score is not None
        assert loaded.composite_score.value.value == pytest.approx(5.0)

        history = await read_repo.score_history(tenant_id, profile.profile_id)
        assert len(history) == 1
        assert history[0].value.value == pytest.approx(5.0)
    finally:
        await read_session.rollback()
        await read_session.close()


@pytest.mark.asyncio
async def test_save_and_get_round_trip(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    profile = make_profile(tenant_id, subject_reference="asset-round-trip")

    await repo.save(profile)
    await re_session.commit()

    loaded = await repo.get(tenant_id, profile.profile_id)
    assert loaded is not None
    assert loaded.profile_id == profile.profile_id
    assert loaded.tenant_id == tenant_id
    assert loaded.subject_reference == "asset-round-trip"
    assert loaded.status == RiskProfileStatus.OPEN
    assert loaded.composite_score is None
    assert len(loaded.contributions) == 1
    assert loaded.contributions[0].dimension == RiskDimension.VULNERABILITY


@pytest.mark.asyncio
async def test_get_returns_none_for_unknown_profile(re_session) -> None:
    repo = PgEnterpriseRiskProfileRepository(re_session)
    assert await repo.get(make_tenant_id(), RiskProfileId.generate()) is None


@pytest.mark.asyncio
async def test_get_enforces_tenant_isolation(re_session) -> None:
    owner_tenant = make_tenant_id()
    other_tenant = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    profile = make_profile(owner_tenant)
    await repo.save(profile)
    await re_session.commit()

    # A profile that exists under a different tenant must be
    # indistinguishable from "doesn't exist" — never leak existence.
    assert await repo.get(other_tenant, profile.profile_id) is None
    assert await repo.get(owner_tenant, profile.profile_id) is not None


@pytest.mark.asyncio
async def test_save_full_aggregate_reconstruction_with_composite_score(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    now = datetime.now(UTC)
    contributions = (
        make_contribution(tenant_id, dimension=RiskDimension.VULNERABILITY, normalized_value=8.0),
        make_contribution(tenant_id, dimension=RiskDimension.CLOUD, normalized_value=4.0),
    )
    composite = make_composite_score(value=6.0, computed_at=now)
    profile = make_profile(
        tenant_id,
        contributions=contributions,
        composite_score=composite,
        now=now,
    )

    await repo.save(profile)
    await re_session.commit()

    loaded = await repo.get(tenant_id, profile.profile_id)
    assert loaded is not None
    assert loaded.composite_score is not None
    assert loaded.composite_score.value.value == pytest.approx(6.0)
    assert loaded.composite_score.weight_profile_id == "default-v1"
    assert len(loaded.contributions) == 2
    dims = {c.dimension for c in loaded.contributions}
    assert dims == {RiskDimension.VULNERABILITY, RiskDimension.CLOUD}
    # signal reference round-trips too
    vuln = next(c for c in loaded.contributions if c.dimension == RiskDimension.VULNERABILITY)
    assert vuln.source_signal.tenant_id == tenant_id
    assert vuln.source_signal.source_context == "vulnerability_engine"


@pytest.mark.asyncio
async def test_save_replaces_contributions_on_recompute(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    profile = make_profile(tenant_id)
    await repo.save(profile)
    await re_session.commit()

    now = datetime.now(UTC)
    new_contribution = make_contribution(
        tenant_id, dimension=RiskDimension.IDENTITY, normalized_value=3.0, computed_at=now
    )
    profile.recompute_score(
        tenant_id, make_composite_score(value=3.0, computed_at=now), (new_contribution,), now
    )
    await repo.save(profile)
    await re_session.commit()

    loaded = await repo.get(tenant_id, profile.profile_id)
    assert loaded is not None
    assert len(loaded.contributions) == 1
    assert loaded.contributions[0].dimension == RiskDimension.IDENTITY


@pytest.mark.asyncio
async def test_save_appends_score_history_on_each_recompute(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    t0 = datetime.now(UTC)
    profile = make_profile(tenant_id, now=t0)
    await repo.save(profile)
    await re_session.commit()

    t1 = t0 + timedelta(minutes=5)
    profile.recompute_score(
        tenant_id,
        make_composite_score(value=5.0, computed_at=t1),
        (make_contribution(tenant_id, computed_at=t1),),
        t1,
    )
    await repo.save(profile)
    await re_session.commit()

    t2 = t1 + timedelta(minutes=5)
    profile.recompute_score(
        tenant_id,
        make_composite_score(value=8.5, computed_at=t2),
        (make_contribution(tenant_id, computed_at=t2),),
        t2,
    )
    await repo.save(profile)
    await re_session.commit()

    history = await repo.score_history(tenant_id, profile.profile_id)
    assert [snap.value.value for snap in history] == pytest.approx([5.0, 8.5])
    assert [snap.computed_at for snap in history] == [t1, t2]


@pytest.mark.asyncio
async def test_score_history_is_tenant_scoped(re_session) -> None:
    tenant_id = make_tenant_id()
    other_tenant = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    now = datetime.now(UTC)
    profile = make_profile(
        tenant_id, composite_score=make_composite_score(computed_at=now), now=now
    )
    await repo.save(profile)
    await re_session.commit()

    assert await repo.score_history(tenant_id, profile.profile_id) != []
    assert await repo.score_history(other_tenant, profile.profile_id) == []


@pytest.mark.asyncio
async def test_list_filters_by_status_and_subject_reference(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    open_profile = make_profile(tenant_id, subject_reference="asset-a")
    closed_profile = make_profile(tenant_id, subject_reference="asset-b")
    closed_profile.close(tenant_id, datetime.now(UTC))
    await repo.save(open_profile)
    await repo.save(closed_profile)
    await re_session.commit()

    all_profiles = await repo.list(tenant_id)
    assert {p.profile_id for p in all_profiles} == {
        open_profile.profile_id,
        closed_profile.profile_id,
    }

    only_closed = await repo.list(tenant_id, status=RiskProfileStatus.CLOSED)
    assert [p.profile_id for p in only_closed] == [closed_profile.profile_id]

    only_asset_a = await repo.list(tenant_id, subject_reference="asset-a")
    assert [p.profile_id for p in only_asset_a] == [open_profile.profile_id]


@pytest.mark.asyncio
async def test_list_supports_pagination(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    for i in range(5):
        await repo.save(make_profile(tenant_id, subject_reference=f"asset-{i}"))
    await re_session.commit()

    page_1 = await repo.list(tenant_id, limit=2, offset=0)
    page_2 = await repo.list(tenant_id, limit=2, offset=2)
    assert len(page_1) == 2
    assert len(page_2) == 2
    assert {p.profile_id for p in page_1}.isdisjoint({p.profile_id for p in page_2})


@pytest.mark.asyncio
async def test_list_is_tenant_scoped(re_session) -> None:
    tenant_a = make_tenant_id()
    tenant_b = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    await repo.save(make_profile(tenant_a))
    await repo.save(make_profile(tenant_b))
    await re_session.commit()

    assert len(await repo.list(tenant_a)) == 1
    assert len(await repo.list(tenant_b)) == 1


@pytest.mark.asyncio
async def test_save_persists_lifecycle_status_transitions(re_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgEnterpriseRiskProfileRepository(re_session)
    profile = make_profile(tenant_id)
    await repo.save(profile)
    await re_session.commit()

    now = datetime.now(UTC)
    profile.acknowledge(tenant_id, now)
    await repo.save(profile)
    await re_session.commit()

    loaded = await repo.get(tenant_id, profile.profile_id)
    assert loaded is not None
    assert loaded.status == RiskProfileStatus.ACKNOWLEDGED

    expires_at = now + timedelta(days=30)
    profile.accept(tenant_id, expires_at, now)
    await repo.save(profile)
    await re_session.commit()

    loaded = await repo.get(tenant_id, profile.profile_id)
    assert loaded is not None
    assert loaded.status == RiskProfileStatus.ACCEPTED
    assert loaded.accepted_expires_at == expires_at

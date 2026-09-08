from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignLifecycleStatus,
    CampaignMotivation,
    CampaignObjectiveType,
    CampaignStatus,
    CampaignTargetSector,
)
from campaign_intel.domain.value_objects.evidence import EvidenceCitation
from campaign_intel.domain.value_objects.identifiers import CampaignId
from campaign_intel.domain.value_objects.taxonomy import CampaignAlias, CampaignObjective
from campaign_intel.domain.value_objects.timeline import CampaignTimeline
from campaign_intel.infrastructure.persistence.exceptions import (
    CampaignIntelIntegrityError,
    OptimisticLockConflictError,
)
from campaign_intel.infrastructure.persistence.repositories.pg_campaign_repository import (
    PgCampaignRepository,
)
from tests.campaign_intel.infrastructure.helpers import (
    make_attribution,
    make_campaign,
    make_tenant_id,
    random_name,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]

NOW = datetime(2026, 8, 5, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)


@pytest.fixture
def repo(cp_session: AsyncSession) -> PgCampaignRepository:
    return PgCampaignRepository(cp_session)


async def test_save_then_get_round_trips_every_field(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    tenant = make_tenant_id()
    campaign = make_campaign(tenant_id=tenant)
    campaign.motivation = CampaignMotivation.ESPIONAGE
    campaign.confidence = CampaignConfidence.VERY_HIGH
    campaign.timeline = CampaignTimeline(first_observed=NOW, last_observed=LATER)
    campaign.add_alias(tenant, CampaignAlias("APT10"), LATER)
    campaign.add_objective(
        tenant, CampaignObjective(CampaignObjectiveType.ESPIONAGE, "steal IP"), LATER
    )
    campaign.add_region(tenant, "EU", LATER)
    campaign.add_target_sector(tenant, CampaignTargetSector.TECHNOLOGY, LATER)
    campaign.add_evidence_citation(tenant, EvidenceCitation("https://example.test/r"), LATER)
    campaign.add_source_attribution(tenant, make_attribution("vendor-x"), LATER)
    campaign.transition_status(tenant, CampaignStatus.ONGOING, make_attribution(), LATER)

    await repo.save(campaign)
    await cp_session.commit()

    loaded = await repo.get(tenant, campaign.campaign_id)
    assert loaded is not None
    assert loaded.canonical_name == campaign.canonical_name
    assert loaded.motivation is CampaignMotivation.ESPIONAGE
    assert loaded.confidence is CampaignConfidence.VERY_HIGH
    assert loaded.status is CampaignStatus.ONGOING
    assert loaded.lifecycle_status is CampaignLifecycleStatus.ACTIVE
    assert loaded.timeline is not None
    assert loaded.timeline.first_observed == NOW
    assert loaded.timeline.last_observed == LATER
    assert loaded.aliases == (CampaignAlias("APT10"),)
    assert loaded.objectives == (CampaignObjective(CampaignObjectiveType.ESPIONAGE, "steal IP"),)
    assert loaded.regions == ("EU",)
    assert loaded.target_sectors == (CampaignTargetSector.TECHNOLOGY,)
    assert loaded.evidence_citations == (EvidenceCitation("https://example.test/r"),)
    assert loaded.source_attributions[0].source_system == "vendor-x"
    assert loaded.source_attributions[0].confidence is CampaignConfidence.HIGH
    assert [v.version for v in loaded.version_history] == [1, 2, 3, 4, 5, 6, 7, 8]


async def test_null_timeline_round_trips_as_none(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    await repo.save(campaign)
    await cp_session.commit()
    loaded = await repo.get(None, campaign.campaign_id)
    assert loaded is not None
    assert loaded.timeline is None


async def test_get_is_tenant_scoped(repo: PgCampaignRepository, cp_session: AsyncSession) -> None:
    tenant = make_tenant_id()
    campaign = make_campaign(tenant_id=tenant)
    await repo.save(campaign)
    await cp_session.commit()

    assert await repo.get(make_tenant_id(), campaign.campaign_id) is None
    assert await repo.get(None, campaign.campaign_id) is None
    assert await repo.get(tenant, campaign.campaign_id) is not None


async def test_global_record_only_visible_in_global_scope(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    await repo.save(campaign)
    await cp_session.commit()
    assert await repo.get(None, campaign.campaign_id) is not None
    assert await repo.get(make_tenant_id(), campaign.campaign_id) is None


async def test_get_any_ignores_scope(repo: PgCampaignRepository, cp_session: AsyncSession) -> None:
    tenant = make_tenant_id()
    campaign = make_campaign(tenant_id=tenant)
    await repo.save(campaign)
    await cp_session.commit()
    found = await repo.get_any(campaign.campaign_id)
    assert found is not None
    assert found.tenant_id == tenant


async def test_get_any_returns_none_for_unknown(repo: PgCampaignRepository) -> None:
    assert await repo.get_any(CampaignId.generate()) is None


async def test_get_by_canonical_name_is_scoped(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    tenant = make_tenant_id()
    name = random_name()
    campaign = make_campaign(tenant_id=tenant, canonical_name=name)
    await repo.save(campaign)
    await cp_session.commit()
    assert await repo.get_by_canonical_name(tenant, name) is not None
    assert await repo.get_by_canonical_name(None, name) is None


async def test_duplicate_identity_in_same_scope_violates_partial_unique_index(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    tenant = make_tenant_id()
    name = random_name()
    await repo.save(make_campaign(tenant_id=tenant, canonical_name=name))
    await cp_session.commit()

    with pytest.raises(CampaignIntelIntegrityError):
        await repo.save(make_campaign(tenant_id=tenant, canonical_name=name))
        await cp_session.commit()
    await cp_session.rollback()


async def test_duplicate_global_identity_is_rejected(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    name = random_name()
    await repo.save(make_campaign(tenant_id=None, canonical_name=name))
    await cp_session.commit()

    with pytest.raises(CampaignIntelIntegrityError):
        await repo.save(make_campaign(tenant_id=None, canonical_name=name))
        await cp_session.commit()
    await cp_session.rollback()


async def test_same_name_allowed_across_distinct_scopes(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    name = random_name()
    await repo.save(make_campaign(tenant_id=None, canonical_name=name))
    await repo.save(make_campaign(tenant_id=make_tenant_id(), canonical_name=name))
    await repo.save(make_campaign(tenant_id=make_tenant_id(), canonical_name=name))
    await cp_session.commit()


async def test_row_version_increments_on_update(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    await repo.save(campaign)
    await cp_session.commit()
    assert campaign.row_version == 1

    campaign.add_alias(None, CampaignAlias("a1"), LATER)
    await repo.save(campaign)
    await cp_session.commit()
    assert campaign.row_version == 2


async def test_stale_write_raises_optimistic_lock_conflict(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    await repo.save(campaign)
    await cp_session.commit()

    fresh = await repo.get(None, campaign.campaign_id)
    assert fresh is not None
    fresh.add_alias(None, CampaignAlias("winner"), LATER)
    await repo.save(fresh)
    await cp_session.commit()

    campaign.add_alias(None, CampaignAlias("loser"), LATER)
    with pytest.raises(OptimisticLockConflictError):
        await repo.save(campaign)
    await cp_session.rollback()


async def test_version_history_is_append_only_across_saves(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    await repo.save(campaign)
    await cp_session.commit()
    for i in range(3):
        campaign.add_alias(None, CampaignAlias(f"a{i}"), LATER)
        await repo.save(campaign)
        await cp_session.commit()

    loaded = await repo.get(None, campaign.campaign_id)
    assert loaded is not None
    assert [v.version for v in loaded.version_history] == [1, 2, 3, 4]


async def test_child_collections_are_wholesale_replaced(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    campaign.add_alias(None, CampaignAlias("first"), LATER)
    await repo.save(campaign)
    await cp_session.commit()

    campaign.aliases = (CampaignAlias("second"),)
    await repo.save(campaign)
    await cp_session.commit()

    loaded = await repo.get(None, campaign.campaign_id)
    assert loaded is not None
    assert loaded.aliases == (CampaignAlias("second"),)


async def test_both_status_axes_persist_independently(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    campaign = make_campaign(tenant_id=None)
    campaign.transition_status(None, CampaignStatus.CONCLUDED, make_attribution(), LATER)
    campaign.deprecate(None, make_attribution(), LATER)
    await repo.save(campaign)
    await cp_session.commit()

    loaded = await repo.get(None, campaign.campaign_id)
    assert loaded is not None
    assert loaded.status is CampaignStatus.CONCLUDED
    assert loaded.lifecycle_status is CampaignLifecycleStatus.DEPRECATED


async def test_lifecycle_and_superseded_by_persist(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    successor = make_campaign(tenant_id=None)
    campaign = make_campaign(tenant_id=None)
    campaign.supersede(None, successor.campaign_id, make_attribution(), LATER)
    await repo.save(successor)
    await repo.save(campaign)
    await cp_session.commit()

    loaded = await repo.get(None, campaign.campaign_id)
    assert loaded is not None
    assert loaded.lifecycle_status is CampaignLifecycleStatus.SUPERSEDED
    assert loaded.superseded_by == successor.campaign_id


async def test_list_filters_and_paginates(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    tenant = make_tenant_id()
    espionage = make_campaign(tenant_id=tenant)
    espionage.motivation = CampaignMotivation.ESPIONAGE
    espionage.add_target_sector(tenant, CampaignTargetSector.TECHNOLOGY, LATER)
    espionage.transition_status(tenant, CampaignStatus.ONGOING, make_attribution(), LATER)

    heist = make_campaign(tenant_id=tenant)
    heist.motivation = CampaignMotivation.FINANCIAL
    heist.add_target_sector(tenant, CampaignTargetSector.FINANCE, LATER)
    heist.transition_status(tenant, CampaignStatus.CONCLUDED, make_attribution(), LATER)
    heist.deprecate(tenant, make_attribution(), LATER)

    await repo.save(espionage)
    await repo.save(heist)
    await cp_session.commit()

    by_status = await repo.list(tenant, status=CampaignStatus.ONGOING)
    assert [c.campaign_id for c in by_status] == [espionage.campaign_id]

    by_motivation = await repo.list(tenant, motivation=CampaignMotivation.FINANCIAL)
    assert [c.campaign_id for c in by_motivation] == [heist.campaign_id]

    by_sector = await repo.list(tenant, target_sector=CampaignTargetSector.TECHNOLOGY)
    assert [c.campaign_id for c in by_sector] == [espionage.campaign_id]

    by_lifecycle = await repo.list(tenant, lifecycle_status=CampaignLifecycleStatus.DEPRECATED)
    assert [c.campaign_id for c in by_lifecycle] == [heist.campaign_id]

    assert len(await repo.list(tenant, limit=1)) == 1
    assert len(await repo.list(tenant, limit=10)) == 2


async def test_list_never_leaks_across_scopes(
    repo: PgCampaignRepository, cp_session: AsyncSession
) -> None:
    tenant = make_tenant_id()
    await repo.save(make_campaign(tenant_id=tenant))
    await repo.save(make_campaign(tenant_id=None))
    await cp_session.commit()

    assert all(c.tenant_id == tenant for c in await repo.list(tenant))
    assert await repo.list(make_tenant_id()) == []

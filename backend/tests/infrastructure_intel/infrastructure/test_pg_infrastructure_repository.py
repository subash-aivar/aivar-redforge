"""Real-PostgreSQL integration tests for `PgInfrastructureRepository`."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from infrastructure_intel.domain.value_objects.enums import (
    CloudProvider,
    InfrastructureLifecycleStatus,
    InfrastructureType,
)
from infrastructure_intel.domain.value_objects.evidence import EvidenceCitation
from infrastructure_intel.domain.value_objects.hosting import (
    CloudProviderRef,
    HostingProviderRef,
    NetworkOwnership,
    Region,
)
from infrastructure_intel.domain.value_objects.identifiers import InfrastructureId
from infrastructure_intel.infrastructure.persistence.exceptions import (
    InfrastructureIntelIntegrityError,
    OptimisticLockConflictError,
)
from infrastructure_intel.infrastructure.persistence.repositories.pg_infrastructure_repository import (
    PgInfrastructureRepository,
)
from tests.infrastructure_intel.infrastructure.helpers import (
    make_attribution,
    make_infrastructure,
    make_tenant_id,
    random_asn,
)

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]

NOW = datetime(2026, 8, 6, tzinfo=UTC)
T = InfrastructureType


async def test_save_then_get_round_trips_the_aggregate(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant_id)
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(tenant_id, record.infrastructure_id)
    assert loaded is not None
    assert loaded.infrastructure_id == record.infrastructure_id
    assert loaded.normalized_identifier == record.normalized_identifier
    assert loaded.infrastructure_type is T.ASN
    assert loaded.tenant_id == tenant_id
    assert loaded.lifecycle_status is InfrastructureLifecycleStatus.ACTIVE
    assert loaded.row_version == 1


async def test_a_global_record_round_trips_with_a_null_tenant(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure(tenant_id=None)
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(None, record.infrastructure_id)
    assert loaded is not None
    assert loaded.tenant_id is None


async def test_all_facets_and_child_collections_round_trip(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant_id)
    record.set_hosting_provider(tenant_id, HostingProviderRef(provider_name="OVH"), NOW)
    record.set_cloud_provider(tenant_id, CloudProviderRef(provider=CloudProvider.AWS), NOW)
    record.add_region(tenant_id, Region(region_code="us-east-1"), NOW)
    record.add_region(tenant_id, Region(region_code="eu-west-1"), NOW)
    record.set_network_ownership(
        tenant_id,
        NetworkOwnership(
            registrant_organization="Shady Hosting BV",
            abuse_contact="abuse@shady.example",
            notes="RIR record",
        ),
        NOW,
    )
    record.add_evidence_citation(tenant_id, EvidenceCitation("https://vendor/report"), NOW)
    record.add_source_attribution(tenant_id, make_attribution(), NOW)
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(tenant_id, record.infrastructure_id)
    assert loaded is not None
    assert loaded.hosting_provider == HostingProviderRef(provider_name="OVH")
    assert loaded.cloud_provider == CloudProviderRef(provider=CloudProvider.AWS)
    assert {r.region_code for r in loaded.regions} == {"us-east-1", "eu-west-1"}
    assert loaded.network_ownership is not None
    assert loaded.network_ownership.registrant_organization == "Shady Hosting BV"
    assert loaded.network_ownership.abuse_contact == "abuse@shady.example"
    assert loaded.network_ownership.notes == "RIR record"
    assert len(loaded.evidence_citations) == 1
    assert len(loaded.source_attributions) == 1
    assert loaded.source_attributions[0].source_system == "redforge-analyst"
    assert len(loaded.version_history) == 8


async def test_optional_facets_stay_none_when_never_asserted(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure()
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(None, record.infrastructure_id)
    assert loaded is not None
    assert loaded.hosting_provider is None
    assert loaded.cloud_provider is None
    assert loaded.network_ownership is None
    assert loaded.regions == ()


async def test_version_history_is_ordered_and_append_only(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure()
    await repo.save(record)
    await ii_session.commit()

    for code in ("us-east-1", "eu-west-1", "ap-southeast-2"):
        loaded = await repo.get(None, record.infrastructure_id)
        assert loaded is not None
        loaded.add_region(None, Region(region_code=code), NOW)
        await repo.save(loaded)
        await ii_session.commit()

    final = await repo.get(None, record.infrastructure_id)
    assert final is not None
    assert [v.version for v in final.version_history] == [1, 2, 3, 4]


async def test_get_is_scoped_and_a_foreign_scope_reads_as_missing(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant_id)
    await repo.save(record)
    await ii_session.commit()

    assert await repo.get(make_tenant_id(), record.infrastructure_id) is None
    assert await repo.get(None, record.infrastructure_id) is None


async def test_get_any_ignores_scope_for_ownership_resolution(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    record = make_infrastructure(tenant_id=tenant_id)
    await repo.save(record)
    await ii_session.commit()

    found = await repo.get_any(record.infrastructure_id)
    assert found is not None
    assert found.tenant_id == tenant_id


async def test_get_any_returns_none_for_an_unknown_id(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    assert await repo.get_any(InfrastructureId.generate()) is None


async def test_get_by_identity_is_scoped(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    asn = random_asn()
    record = make_infrastructure(tenant_id=tenant_id, normalized_identifier=asn)
    await repo.save(record)
    await ii_session.commit()

    assert await repo.get_by_identity(tenant_id, T.ASN, asn) is not None
    assert await repo.get_by_identity(None, T.ASN, asn) is None
    assert await repo.get_by_identity(make_tenant_id(), T.ASN, asn) is None


async def test_get_by_identity_discriminates_on_type(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    shared = f"shared{__import__('random').randint(1, 10**12)}.example.com"
    await repo.save(make_infrastructure(infrastructure_type=T.DOMAIN, normalized_identifier=shared))
    await ii_session.commit()

    assert await repo.get_by_identity(None, T.DOMAIN, shared) is not None
    assert await repo.get_by_identity(None, T.HOSTING_PROVIDER, shared) is None


async def test_the_same_identity_may_coexist_in_global_and_tenant_scope(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    asn = random_asn()
    await repo.save(make_infrastructure(tenant_id=None, normalized_identifier=asn))
    await repo.save(make_infrastructure(tenant_id=tenant_id, normalized_identifier=asn))
    await ii_session.commit()

    assert await repo.get_by_identity(None, T.ASN, asn) is not None
    assert await repo.get_by_identity(tenant_id, T.ASN, asn) is not None


async def test_the_global_partial_unique_index_blocks_a_duplicate(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    asn = random_asn()
    await repo.save(make_infrastructure(tenant_id=None, normalized_identifier=asn))
    await ii_session.commit()

    with pytest.raises(InfrastructureIntelIntegrityError):
        await repo.save(make_infrastructure(tenant_id=None, normalized_identifier=asn))
        await ii_session.commit()
    await ii_session.rollback()


async def test_the_tenant_partial_unique_index_blocks_a_duplicate(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    asn = random_asn()
    await repo.save(make_infrastructure(tenant_id=tenant_id, normalized_identifier=asn))
    await ii_session.commit()

    with pytest.raises(InfrastructureIntelIntegrityError):
        await repo.save(make_infrastructure(tenant_id=tenant_id, normalized_identifier=asn))
        await ii_session.commit()
    await ii_session.rollback()


async def test_the_unique_index_does_not_collide_across_types(ii_session) -> None:
    """The identity index spans (type, identifier) — the same string
    under two types must both persist."""
    repo = PgInfrastructureRepository(ii_session)
    shared = f"shared{__import__('random').randint(1, 10**12)}.example.com"
    await repo.save(make_infrastructure(infrastructure_type=T.DOMAIN, normalized_identifier=shared))
    await repo.save(
        make_infrastructure(infrastructure_type=T.HOSTING_PROVIDER, normalized_identifier=shared)
    )
    await ii_session.commit()

    assert await repo.get_by_identity(None, T.DOMAIN, shared) is not None
    assert await repo.get_by_identity(None, T.HOSTING_PROVIDER, shared) is not None


async def test_row_version_increments_on_every_update(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure()
    await repo.save(record)
    await ii_session.commit()
    assert record.row_version == 1

    record.add_region(None, Region(region_code="us-east-1"), NOW)
    await repo.save(record)
    await ii_session.commit()
    assert record.row_version == 2

    record.add_region(None, Region(region_code="eu-west-1"), NOW)
    await repo.save(record)
    await ii_session.commit()
    assert record.row_version == 3


async def test_a_stale_writer_hits_the_optimistic_lock(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure()
    await repo.save(record)
    await ii_session.commit()

    first = await repo.get(None, record.infrastructure_id)
    second = await repo.get(None, record.infrastructure_id)
    assert first is not None and second is not None

    first.add_region(None, Region(region_code="winner"), NOW)
    await repo.save(first)
    await ii_session.commit()

    second.add_region(None, Region(region_code="loser"), NOW)
    with pytest.raises(OptimisticLockConflictError):
        await repo.save(second)


async def test_lifecycle_and_superseded_by_persist(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    successor = make_infrastructure()
    record = make_infrastructure()
    await repo.save(successor)
    await repo.save(record)
    await ii_session.commit()

    record.supersede(None, successor.infrastructure_id, make_attribution(), NOW)
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(None, record.infrastructure_id)
    assert loaded is not None
    assert loaded.lifecycle_status is InfrastructureLifecycleStatus.SUPERSEDED
    assert loaded.superseded_by == successor.infrastructure_id


async def test_reactivation_clears_superseded_by_in_the_database(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure()
    await repo.save(record)
    await ii_session.commit()

    record.deprecate(None, make_attribution(), NOW)
    await repo.save(record)
    await ii_session.commit()
    record.reactivate(None, make_attribution(), NOW)
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(None, record.infrastructure_id)
    assert loaded is not None
    assert loaded.superseded_by is None
    assert loaded.lifecycle_status is InfrastructureLifecycleStatus.ACTIVE


async def test_list_is_scoped_to_the_requested_owner(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    mine = make_infrastructure(tenant_id=tenant_id)
    await repo.save(mine)
    await repo.save(make_infrastructure(tenant_id=make_tenant_id()))
    await ii_session.commit()

    ids = {str(r.infrastructure_id) for r in await repo.list(tenant_id)}
    assert ids == {str(mine.infrastructure_id)}


async def test_list_filters_by_lifecycle_status_and_type(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    asn = make_infrastructure(tenant_id=tenant_id, infrastructure_type=T.ASN)
    domain = make_infrastructure(tenant_id=tenant_id, infrastructure_type=T.DOMAIN)
    await repo.save(asn)
    await repo.save(domain)
    await ii_session.commit()
    domain.revoke(tenant_id, make_attribution(), NOW)
    await repo.save(domain)
    await ii_session.commit()

    by_type = await repo.list(tenant_id, infrastructure_type=T.ASN)
    assert [str(r.infrastructure_id) for r in by_type] == [str(asn.infrastructure_id)]

    active = await repo.list(tenant_id, lifecycle_status=InfrastructureLifecycleStatus.ACTIVE)
    assert [str(r.infrastructure_id) for r in active] == [str(asn.infrastructure_id)]


async def test_list_filters_by_cloud_provider(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    aws = make_infrastructure(tenant_id=tenant_id)
    aws.set_cloud_provider(tenant_id, CloudProviderRef(provider=CloudProvider.AWS), NOW)
    gcp = make_infrastructure(tenant_id=tenant_id)
    gcp.set_cloud_provider(tenant_id, CloudProviderRef(provider=CloudProvider.GCP), NOW)
    await repo.save(aws)
    await repo.save(gcp)
    await ii_session.commit()

    found = await repo.list(tenant_id, cloud_provider=CloudProvider.GCP)
    assert [str(r.infrastructure_id) for r in found] == [str(gcp.infrastructure_id)]


async def test_list_paginates_with_a_stable_order(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    tenant_id = make_tenant_id()
    for _ in range(5):
        await repo.save(make_infrastructure(tenant_id=tenant_id))
    await ii_session.commit()

    page1 = await repo.list(tenant_id, limit=2, offset=0)
    page2 = await repo.list(tenant_id, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {str(r.infrastructure_id) for r in page1}.isdisjoint(
        {str(r.infrastructure_id) for r in page2}
    )


async def test_child_collections_are_wholesale_replaced_not_appended(ii_session) -> None:
    repo = PgInfrastructureRepository(ii_session)
    record = make_infrastructure()
    record.add_region(None, Region(region_code="a-region"), NOW)
    await repo.save(record)
    await ii_session.commit()

    loaded = await repo.get(None, record.infrastructure_id)
    assert loaded is not None
    loaded.add_region(None, Region(region_code="b-region"), NOW)
    await repo.save(loaded)
    await ii_session.commit()

    final = await repo.get(None, record.infrastructure_id)
    assert final is not None
    assert {r.region_code for r in final.regions} == {"a-region", "b-region"}

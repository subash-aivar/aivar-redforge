"""End-to-end API tests for infrastructure_intel over a real ASGI app
and a real PostgreSQL database."""

from __future__ import annotations

import os
import random
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"),
        reason="requires TEST_DATABASE_URL (real PostgreSQL)",
    ),
]

BASE = "/api/v1/infrastructure-intel"
EVIDENCE = {
    "source_system": "redforge-analyst",
    "reference": "report-42",
    "observed_at": "2026-08-06T12:00:00+00:00",
    "confidence": "high",
}


def _asn() -> str:
    return f"AS{random.randint(1, 4_000_000_000)}"


async def _observe_tenant(client: AsyncClient, **body: object) -> dict:
    payload = {
        "infrastructure_type": "asn",
        "normalized_identifier": _asn(),
        **body,
    }
    response = await client.post(f"{BASE}/observations/tenant", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


async def _observe_global(client: AsyncClient, **body: object) -> dict:
    payload = {
        "infrastructure_type": "asn",
        "normalized_identifier": _asn(),
        **body,
    }
    response = await client.post(f"{BASE}/observations/global", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


# ── Observation ──────────────────────────────────────────────────────────


async def test_observe_tenant_returns_201_and_a_location_header(
    owner_client: AsyncClient, organization_id
) -> None:
    asn = _asn()
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={
            "infrastructure_type": "asn",
            "normalized_identifier": f"  {asn.lower()} ",
            "confidence": "very_high",
            "hosting_provider": "Shady Hosting BV",
            "cloud_provider": "aws",
            "regions": ["us-east-1"],
            "network_ownership": {
                "registrant_organization": "Shady Hosting BV",
                "abuse_contact": "abuse@shady.example",
            },
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["normalized_identifier"] == asn
    assert body["infrastructure_type"] == "asn"
    assert body["tenant_id"] == str(organization_id)
    assert body["lifecycle_status"] == "active"
    assert body["hosting_provider"] == "Shady Hosting BV"
    assert body["cloud_provider"] == "aws"
    assert body["regions"] == ["us-east-1"]
    assert body["network_ownership"]["abuse_contact"] == "abuse@shady.example"
    assert response.headers["Location"] == f"{BASE}/{body['infrastructure_id']}"


async def test_observe_normalizes_a_domain_identifier(owner_client: AsyncClient) -> None:
    name = f"EVIL{random.randint(1, 10**12)}.Example.COM"
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "domain", "normalized_identifier": f"  {name} "},
    )
    assert response.status_code == 201
    assert response.json()["normalized_identifier"] == name.lower()


async def test_observe_global_requires_platform_authority(
    platform_admin_client: AsyncClient,
) -> None:
    body = await _observe_global(platform_admin_client)
    assert body["tenant_id"] is None


async def test_a_tenant_owner_cannot_observe_a_global_record(owner_client: AsyncClient) -> None:
    """Organization membership never satisfies platform authority."""
    response = await owner_client.post(
        f"{BASE}/observations/global",
        json={"infrastructure_type": "asn", "normalized_identifier": _asn()},
    )
    assert response.status_code == 403


async def test_observe_without_permission_is_forbidden(
    no_permission_client: AsyncClient,
) -> None:
    response = await no_permission_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "asn", "normalized_identifier": _asn()},
    )
    assert response.status_code == 403


async def test_a_duplicate_identity_is_a_conflict(owner_client: AsyncClient) -> None:
    asn = _asn()
    first = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "asn", "normalized_identifier": asn},
    )
    assert first.status_code == 201
    second = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "asn", "normalized_identifier": f"  {asn.lower()}  "},
    )
    assert second.status_code == 409


async def test_the_same_identifier_under_two_types_is_not_a_conflict(
    owner_client: AsyncClient,
) -> None:
    shared = f"shared{random.randint(1, 10**12)}.example.com"
    a = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "domain", "normalized_identifier": shared},
    )
    b = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "hosting_provider", "normalized_identifier": shared},
    )
    assert a.status_code == 201
    assert b.status_code == 201


async def test_an_unnormalizable_identifier_is_unprocessable(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "ip_address", "normalized_identifier": "not-an-ip"},
    )
    assert response.status_code == 422


async def test_an_invalid_enum_value_is_unprocessable(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"infrastructure_type": "not_a_type", "normalized_identifier": "x"},
    )
    assert response.status_code == 422


# ── Reads ────────────────────────────────────────────────────────────────


async def test_get_returns_the_tenant_record_to_its_owner(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.get(f"{BASE}/{created['infrastructure_id']}")
    assert response.status_code == 200
    assert response.json()["infrastructure_id"] == created["infrastructure_id"]


async def test_a_cross_tenant_read_is_a_404_not_a_403(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    """Another tenant's record must be indistinguishable from a record
    that does not exist — a 403 would leak its existence."""
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.get(f"{BASE}/{created['infrastructure_id']}")
    assert response.status_code == 404


async def test_an_unknown_id_is_a_404(owner_client: AsyncClient) -> None:
    from uuid import uuid4

    response = await owner_client.get(f"{BASE}/{uuid4()}")
    assert response.status_code == 404


async def test_a_malformed_id_is_unprocessable(owner_client: AsyncClient) -> None:
    response = await owner_client.get(f"{BASE}/not-a-uuid")
    assert response.status_code == 422


async def test_a_platform_admin_can_read_a_global_record(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await platform_admin_client.get(f"{BASE}/{created['infrastructure_id']}")
    assert response.status_code == 200


async def test_a_tenant_caller_without_platform_authority_cannot_read_a_global_record(
    platform_admin_client: AsyncClient, owner_client: AsyncClient
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await owner_client.get(f"{BASE}/{created['infrastructure_id']}")
    assert response.status_code == 403


# ── Lists ────────────────────────────────────────────────────────────────


async def test_the_tenant_list_returns_only_this_tenant(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.get(BASE)
    assert response.status_code == 200
    body = response.json()
    assert created["infrastructure_id"] in [i["infrastructure_id"] for i in body["items"]]
    assert all(i["tenant_id"] is not None for i in body["items"])


async def test_the_tenant_list_hides_another_tenants_records(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.get(BASE)
    assert created["infrastructure_id"] not in [
        i["infrastructure_id"] for i in response.json()["items"]
    ]


async def test_the_global_list_requires_platform_authority(
    owner_client: AsyncClient, platform_admin_client: AsyncClient
) -> None:
    assert (await owner_client.get(f"{BASE}/global")).status_code == 403
    assert (await platform_admin_client.get(f"{BASE}/global")).status_code == 200


async def test_the_list_filters_by_infrastructure_type(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client, infrastructure_type="asn")
    response = await owner_client.get(BASE, params={"infrastructure_type": "asn"})
    ids = [i["infrastructure_id"] for i in response.json()["items"]]
    assert created["infrastructure_id"] in ids
    other = await owner_client.get(BASE, params={"infrastructure_type": "url"})
    assert created["infrastructure_id"] not in [
        i["infrastructure_id"] for i in other.json()["items"]
    ]


async def test_the_list_filters_by_cloud_provider(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client, cloud_provider="ovh")
    response = await owner_client.get(BASE, params={"cloud_provider": "ovh"})
    assert created["infrastructure_id"] in [
        i["infrastructure_id"] for i in response.json()["items"]
    ]


async def test_the_list_filters_by_lifecycle_status(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    await owner_client.patch(
        f"{BASE}/{created['infrastructure_id']}/revoke", json={"evidence": EVIDENCE}
    )
    revoked = await owner_client.get(BASE, params={"lifecycle_status": "revoked"})
    assert created["infrastructure_id"] in [i["infrastructure_id"] for i in revoked.json()["items"]]
    active = await owner_client.get(BASE, params={"lifecycle_status": "active"})
    assert created["infrastructure_id"] not in [
        i["infrastructure_id"] for i in active.json()["items"]
    ]


async def test_the_list_rejects_an_out_of_range_limit(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(BASE, params={"limit": 0})).status_code == 422
    assert (await owner_client.get(BASE, params={"limit": 100000})).status_code == 422


async def test_the_list_reports_pagination_metadata(owner_client: AsyncClient) -> None:
    await _observe_tenant(owner_client)
    response = await owner_client.get(BASE, params={"limit": 1, "offset": 0})
    body = response.json()
    assert body["limit"] == 1
    assert body["offset"] == 0
    assert body["count"] == len(body["items"])


# ── Enrichment ───────────────────────────────────────────────────────────


async def test_set_hosting_provider(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/hosting-provider",
        json={"provider_name": "OVH"},
    )
    assert response.status_code == 200
    assert response.json()["hosting_provider"] == "OVH"


async def test_set_cloud_provider(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/cloud-provider", json={"provider": "azure"}
    )
    assert response.status_code == 200
    assert response.json()["cloud_provider"] == "azure"


async def test_set_cloud_provider_rejects_an_unknown_value(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/cloud-provider",
        json={"provider": "oracle_cloud"},
    )
    assert response.status_code == 422


async def test_add_region(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/regions", json={"region_code": "eu-west-1"}
    )
    assert response.status_code == 200
    assert response.json()["regions"] == ["eu-west-1"]


async def test_set_network_ownership(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/network-ownership",
        json={
            "ownership": {
                "registrant_organization": "Shady Hosting BV",
                "abuse_contact": "abuse@shady.example",
                "notes": "RIR record",
            }
        },
    )
    assert response.status_code == 200
    ownership = response.json()["network_ownership"]
    assert ownership["registrant_organization"] == "Shady Hosting BV"
    assert ownership["notes"] == "RIR record"


async def test_add_evidence_citation(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/evidence-citations",
        json={"citation": "https://vendor/report"},
    )
    assert response.status_code == 200
    assert response.json()["evidence_citations"] == ["https://vendor/report"]


async def test_add_source_attribution(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/source-attributions",
        json={"attribution": EVIDENCE},
    )
    assert response.status_code == 200
    attributions = response.json()["source_attributions"]
    assert len(attributions) == 1
    assert attributions[0]["source_system"] == "redforge-analyst"


async def test_enrichment_across_tenants_is_a_404(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.post(
        f"{BASE}/{created['infrastructure_id']}/regions", json={"region_code": "x"}
    )
    assert response.status_code == 404


async def test_a_tenant_caller_cannot_mutate_a_global_record(
    platform_admin_client: AsyncClient, owner_client: AsyncClient
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await owner_client.post(
        f"{BASE}/{created['infrastructure_id']}/regions", json={"region_code": "x"}
    )
    assert response.status_code == 403


async def test_a_platform_admin_can_mutate_a_global_record(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await platform_admin_client.post(
        f"{BASE}/{created['infrastructure_id']}/regions", json={"region_code": "x"}
    )
    assert response.status_code == 200


# ── Record lifecycle ─────────────────────────────────────────────────────


async def test_deprecate_then_reactivate(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    deprecated = await owner_client.patch(
        f"{BASE}/{created['infrastructure_id']}/deprecate", json={"evidence": EVIDENCE}
    )
    assert deprecated.status_code == 200
    assert deprecated.json()["lifecycle_status"] == "deprecated"

    reactivated = await owner_client.patch(
        f"{BASE}/{created['infrastructure_id']}/reactivate", json={"evidence": EVIDENCE}
    )
    assert reactivated.status_code == 200
    assert reactivated.json()["lifecycle_status"] == "active"


async def test_revoke_is_terminal_and_a_further_transition_is_a_conflict(
    owner_client: AsyncClient,
) -> None:
    created = await _observe_tenant(owner_client)
    revoked = await owner_client.patch(
        f"{BASE}/{created['infrastructure_id']}/revoke", json={"evidence": EVIDENCE}
    )
    assert revoked.status_code == 200
    conflict = await owner_client.patch(
        f"{BASE}/{created['infrastructure_id']}/reactivate", json={"evidence": EVIDENCE}
    )
    assert conflict.status_code == 409


async def test_supersede_records_the_successor(owner_client: AsyncClient) -> None:
    old = await _observe_tenant(owner_client)
    new = await _observe_tenant(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{old['infrastructure_id']}/supersede",
        json={"superseded_by": new["infrastructure_id"], "evidence": EVIDENCE},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["lifecycle_status"] == "superseded"
    assert body["superseded_by"] == new["infrastructure_id"]


async def test_a_superseded_record_cannot_be_reactivated(owner_client: AsyncClient) -> None:
    old = await _observe_tenant(owner_client)
    new = await _observe_tenant(owner_client)
    await owner_client.patch(
        f"{BASE}/{old['infrastructure_id']}/supersede",
        json={"superseded_by": new["infrastructure_id"], "evidence": EVIDENCE},
    )
    response = await owner_client.patch(
        f"{BASE}/{old['infrastructure_id']}/reactivate", json={"evidence": EVIDENCE}
    )
    assert response.status_code == 409


async def test_a_lifecycle_change_across_tenants_is_a_404(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.patch(
        f"{BASE}/{created['infrastructure_id']}/deprecate", json={"evidence": EVIDENCE}
    )
    assert response.status_code == 404


async def test_a_malformed_evidence_timestamp_is_unprocessable(
    owner_client: AsyncClient,
) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{created['infrastructure_id']}/deprecate",
        json={"evidence": {**EVIDENCE, "observed_at": "not-a-timestamp"}},
    )
    assert response.status_code == 422


# ── Version history ──────────────────────────────────────────────────────


async def test_version_history_accumulates_across_requests(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    record_id = created["infrastructure_id"]
    await owner_client.post(f"{BASE}/{record_id}/regions", json={"region_code": "us-east-1"})
    await owner_client.post(f"{BASE}/{record_id}/hosting-provider", json={"provider_name": "OVH"})
    final = await owner_client.patch(f"{BASE}/{record_id}/deprecate", json={"evidence": EVIDENCE})
    history = final.json()["version_history"]
    assert [v["version"] for v in history] == [1, 2, 3, 4]
    assert history[-1]["change_summary"] == "Deprecated"
    assert history[-1]["source"] == "redforge-analyst"

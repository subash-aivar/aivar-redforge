from __future__ import annotations

import os
import random
from typing import TYPE_CHECKING
from uuid import uuid4

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

BASE = "/api/v1/campaign-intel"
ATTRIBUTION = {
    "source_system": "redforge-analyst",
    "reference": "ref-1",
    "observed_at": "2026-08-05T00:00:00+00:00",
    "confidence": "high",
    "notes": "",
}


def _name(prefix: str = "campaign") -> str:
    return f"{prefix}{random.randint(1, 10**12)}"


async def _observe_tenant(client: AsyncClient, **body: object) -> dict:
    payload = {"canonical_name": _name(), **body}
    response = await client.post(f"{BASE}/observations/tenant", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


async def _observe_global(client: AsyncClient, **body: object) -> dict:
    payload = {"canonical_name": _name(), **body}
    response = await client.post(f"{BASE}/observations/global", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


# ── Observation ─────────────────────────────────────────────────────────


async def test_observe_tenant_returns_201_with_location(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant", json={"canonical_name": "  CLOUD-" + _name() + "  "}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["canonical_name"] == body["canonical_name"].strip().lower()
    assert body["lifecycle_status"] == "active"
    assert body["status"] == "unknown"
    assert response.headers["Location"].endswith(body["campaign_id"])


async def test_observe_tenant_requires_tenant_permission(
    no_permission_client: AsyncClient,
) -> None:
    response = await no_permission_client.post(
        f"{BASE}/observations/tenant", json={"canonical_name": _name()}
    )
    assert response.status_code == 403


async def test_observe_global_requires_platform_authority(owner_client: AsyncClient) -> None:
    """An org OWNER holding every tenant Permission still cannot create
    a global record."""
    response = await owner_client.post(
        f"{BASE}/observations/global", json={"canonical_name": _name()}
    )
    assert response.status_code == 403


async def test_observe_global_succeeds_for_platform_admin(
    platform_admin_client: AsyncClient,
) -> None:
    body = await _observe_global(platform_admin_client)
    assert body["tenant_id"] is None


async def test_observe_rejects_duplicate_with_409(owner_client: AsyncClient) -> None:
    name = _name()
    assert (
        await owner_client.post(f"{BASE}/observations/tenant", json={"canonical_name": name})
    ).status_code == 201
    conflict = await owner_client.post(
        f"{BASE}/observations/tenant", json={"canonical_name": f"  {name.upper()} "}
    )
    assert conflict.status_code == 409


async def test_observe_rejects_blank_name_with_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(f"{BASE}/observations/tenant", json={"canonical_name": " "})
    assert response.status_code == 422


async def test_observe_rejects_unknown_target_sector_with_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={"canonical_name": _name(), "target_sectors": ["aerospace"]},
    )
    assert response.status_code == 422


async def test_observe_rejects_bad_region_with_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant", json={"canonical_name": _name(), "regions": ["!!"]}
    )
    assert response.status_code == 422


async def test_observe_rejects_reversed_timeline_with_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json={
            "canonical_name": _name(),
            "timeline": {
                "first_observed": "2026-01-01T00:00:00+00:00",
                "last_observed": "2025-01-01T00:00:00+00:00",
            },
        },
    )
    assert response.status_code == 422


async def test_observe_accepts_full_taxonomy(owner_client: AsyncClient) -> None:
    body = await _observe_tenant(
        owner_client,
        status="ongoing",
        motivation="espionage",
        confidence="very_high",
        timeline={"first_observed": "2024-01-01T00:00:00+00:00", "ongoing": True},
        aliases=["APT10"],
        objectives=[{"objective_type": "espionage", "description": "steal IP"}],
        regions=["eu", "us"],
        target_sectors=["technology", "government"],
    )
    assert body["status"] == "ongoing"
    assert body["motivation"] == "espionage"
    assert body["confidence"] == "very_high"
    assert body["aliases"] == ["APT10"]
    assert body["objectives"][0]["objective_type"] == "espionage"
    assert body["regions"] == ["EU", "US"]
    assert body["target_sectors"] == ["technology", "government"]
    assert body["timeline"]["ongoing"] is True


# ── Reads ───────────────────────────────────────────────────────────────


async def test_get_tenant_record(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.get(f"{BASE}/{created['campaign_id']}")
    assert response.status_code == 200
    assert response.json()["campaign_id"] == created["campaign_id"]


async def test_get_cross_tenant_is_404_not_403(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    """A different tenant must not be able to distinguish 'exists but
    not yours' from 'does not exist'."""
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.get(f"{BASE}/{created['campaign_id']}")
    assert response.status_code == 404


async def test_get_unknown_id_is_404(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(f"{BASE}/{uuid4()}")).status_code == 404


async def test_get_malformed_id_is_422(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(f"{BASE}/not-a-uuid")).status_code == 422


async def test_platform_admin_can_read_global_record(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await platform_admin_client.get(f"{BASE}/{created['campaign_id']}")
    assert response.status_code == 200


async def test_tenant_caller_without_platform_authority_cannot_read_global(
    platform_admin_client: AsyncClient, owner_client: AsyncClient
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await owner_client.get(f"{BASE}/{created['campaign_id']}")
    assert response.status_code == 403


async def test_list_tenant_records(owner_client: AsyncClient) -> None:
    await _observe_tenant(owner_client)
    response = await owner_client.get(BASE)
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert all(item["tenant_id"] is not None for item in body["items"])


async def test_list_tenant_requires_permission(no_permission_client: AsyncClient) -> None:
    assert (await no_permission_client.get(BASE)).status_code == 403


async def test_list_global_requires_platform_authority(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(f"{BASE}/global")).status_code == 403


async def test_list_global_for_platform_admin(platform_admin_client: AsyncClient) -> None:
    await _observe_global(platform_admin_client)
    response = await platform_admin_client.get(f"{BASE}/global")
    assert response.status_code == 200
    assert all(item["tenant_id"] is None for item in response.json()["items"])


async def test_list_filters_on_both_axes_independently(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(
        owner_client, status="ongoing", motivation="financial", target_sectors=["finance"]
    )
    cid = created["campaign_id"]

    by_status = await owner_client.get(BASE, params={"status": "ongoing"})
    assert cid in [i["campaign_id"] for i in by_status.json()["items"]]

    by_motivation = await owner_client.get(BASE, params={"motivation": "financial"})
    assert cid in [i["campaign_id"] for i in by_motivation.json()["items"]]

    by_sector = await owner_client.get(BASE, params={"target_sector": "finance"})
    assert cid in [i["campaign_id"] for i in by_sector.json()["items"]]

    by_lifecycle = await owner_client.get(BASE, params={"lifecycle_status": "active"})
    assert cid in [i["campaign_id"] for i in by_lifecycle.json()["items"]]


async def test_list_rejects_out_of_range_limit(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(BASE, params={"limit": 0})).status_code == 422
    assert (await owner_client.get(BASE, params={"limit": 10_000})).status_code == 422


# ── Enrichment ──────────────────────────────────────────────────────────


async def test_add_alias_objective_region_and_sector(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    cid = created["campaign_id"]

    alias = await owner_client.post(f"{BASE}/{cid}/aliases", json={"alias": "APT10"})
    assert alias.status_code == 200
    assert alias.json()["aliases"] == ["APT10"]

    objective = await owner_client.post(
        f"{BASE}/{cid}/objectives",
        json={"objective": {"objective_type": "disruption", "description": "d"}},
    )
    assert objective.json()["objectives"][0]["objective_type"] == "disruption"

    region = await owner_client.post(f"{BASE}/{cid}/regions", json={"region": "apac"})
    assert region.json()["regions"] == ["APAC"]

    sector = await owner_client.post(
        f"{BASE}/{cid}/target-sectors", json={"target_sector": "energy"}
    )
    assert sector.json()["target_sectors"] == ["energy"]
    assert len(sector.json()["version_history"]) == 5


async def test_add_evidence_citation_and_source_attribution(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    cid = created["campaign_id"]

    citation = await owner_client.post(
        f"{BASE}/{cid}/evidence-citations", json={"citation": "https://example.test/r"}
    )
    assert citation.json()["evidence_citations"] == ["https://example.test/r"]

    attribution = await owner_client.post(
        f"{BASE}/{cid}/source-attributions", json={"attribution": ATTRIBUTION}
    )
    assert attribution.status_code == 200
    assert attribution.json()["source_attributions"][0]["confidence"] == "high"


async def test_enrichment_rejects_unknown_sector_with_422(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['campaign_id']}/target-sectors", json={"target_sector": "aerospace"}
    )
    assert response.status_code == 422


async def test_enrichment_cross_tenant_is_404(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.post(
        f"{BASE}/{created['campaign_id']}/aliases", json={"alias": "x"}
    )
    assert response.status_code == 404


async def test_enrichment_on_global_requires_platform_manage(
    platform_admin_client: AsyncClient, owner_client: AsyncClient
) -> None:
    created = await _observe_global(platform_admin_client)
    assert (
        await owner_client.post(f"{BASE}/{created['campaign_id']}/aliases", json={"alias": "x"})
    ).status_code == 403
    assert (
        await platform_admin_client.post(
            f"{BASE}/{created['campaign_id']}/aliases", json={"alias": "x"}
        )
    ).status_code == 200


# ── Real-world status axis ──────────────────────────────────────────────


async def test_transition_status_flow(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    cid = created["campaign_id"]

    ongoing = await owner_client.patch(
        f"{BASE}/{cid}/transition-status",
        json={"target_status": "ongoing", "evidence": ATTRIBUTION},
    )
    assert ongoing.status_code == 200
    assert ongoing.json()["status"] == "ongoing"
    assert ongoing.json()["lifecycle_status"] == "active"

    suspected = await owner_client.patch(
        f"{BASE}/{cid}/transition-status",
        json={"target_status": "suspected_concluded", "evidence": ATTRIBUTION},
    )
    assert suspected.json()["status"] == "suspected_concluded"

    concluded = await owner_client.patch(
        f"{BASE}/{cid}/transition-status",
        json={"target_status": "concluded", "evidence": ATTRIBUTION},
    )
    assert concluded.json()["status"] == "concluded"


async def test_illegal_status_transition_returns_409(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    cid = created["campaign_id"]
    await owner_client.patch(
        f"{BASE}/{cid}/transition-status",
        json={"target_status": "concluded", "evidence": ATTRIBUTION},
    )
    response = await owner_client.patch(
        f"{BASE}/{cid}/transition-status",
        json={"target_status": "ongoing", "evidence": ATTRIBUTION},
    )
    assert response.status_code == 409


async def test_unknown_target_status_is_422(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{created['campaign_id']}/transition-status",
        json={"target_status": "paused", "evidence": ATTRIBUTION},
    )
    assert response.status_code == 422


# ── Record lifecycle axis ───────────────────────────────────────────────


async def test_deprecate_reactivate_supersede_revoke_flow(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    cid = created["campaign_id"]

    deprecated = await owner_client.patch(f"{BASE}/{cid}/deprecate", json={"evidence": ATTRIBUTION})
    assert deprecated.json()["lifecycle_status"] == "deprecated"

    reactivated = await owner_client.patch(
        f"{BASE}/{cid}/reactivate", json={"evidence": ATTRIBUTION}
    )
    assert reactivated.json()["lifecycle_status"] == "active"

    successor = await _observe_tenant(owner_client)
    superseded = await owner_client.patch(
        f"{BASE}/{cid}/supersede",
        json={"superseded_by": successor["campaign_id"], "evidence": ATTRIBUTION},
    )
    assert superseded.json()["lifecycle_status"] == "superseded"
    assert superseded.json()["superseded_by"] == successor["campaign_id"]

    revoked = await owner_client.patch(f"{BASE}/{cid}/revoke", json={"evidence": ATTRIBUTION})
    assert revoked.json()["lifecycle_status"] == "revoked"


async def test_illegal_lifecycle_transition_returns_409(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    cid = created["campaign_id"]
    await owner_client.patch(f"{BASE}/{cid}/revoke", json={"evidence": ATTRIBUTION})
    response = await owner_client.patch(f"{BASE}/{cid}/deprecate", json={"evidence": ATTRIBUTION})
    assert response.status_code == 409


async def test_deprecating_the_record_leaves_real_world_status_untouched(
    owner_client: AsyncClient,
) -> None:
    created = await _observe_tenant(owner_client, status="ongoing")
    cid = created["campaign_id"]
    deprecated = await owner_client.patch(f"{BASE}/{cid}/deprecate", json={"evidence": ATTRIBUTION})
    assert deprecated.json()["status"] == "ongoing"
    assert deprecated.json()["lifecycle_status"] == "deprecated"


async def test_lifecycle_cross_tenant_is_404(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.patch(
        f"{BASE}/{created['campaign_id']}/deprecate", json={"evidence": ATTRIBUTION}
    )
    assert response.status_code == 404


async def test_lifecycle_on_unknown_id_is_404(owner_client: AsyncClient) -> None:
    response = await owner_client.patch(
        f"{BASE}/{uuid4()}/deprecate", json={"evidence": ATTRIBUTION}
    )
    assert response.status_code == 404

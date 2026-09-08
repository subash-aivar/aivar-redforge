from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

BASE = "/api/v1/relationships"
OBSERVED_AT = "2026-08-05T00:00:00+00:00"


def _attribution(source_system: str = "analyst") -> dict[str, Any]:
    return {
        "source_system": source_system,
        "reference": f"ref-{uuid4()}",
        "observed_at": OBSERVED_AT,
        "confidence": "high",
    }


def _observe_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "relationship_type": "malware_to_campaign",
        "source_entity": {"entity_type": "malware", "entity_id": f"m-{uuid4()}"},
        "target_entity": {"entity_type": "campaign", "entity_id": f"c-{uuid4()}"},
        "direction": "unidirectional",
        "confidence": "medium",
    }
    body.update(overrides)
    return body


async def _create_tenant_relationship(client: AsyncClient, **overrides: Any) -> dict[str, Any]:
    response = await client.post(f"{BASE}/observations/tenant", json=_observe_body(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


async def _create_global_relationship(client: AsyncClient, **overrides: Any) -> dict[str, Any]:
    response = await client.post(f"{BASE}/observations/global", json=_observe_body(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


# ── Observation ──────────────────────────────────────────────────────────


async def test_observe_tenant_relationship_returns_201_and_location(
    owner_client: AsyncClient,
) -> None:
    response = await owner_client.post(f"{BASE}/observations/tenant", json=_observe_body())
    assert response.status_code == 201
    body = response.json()
    assert body["lifecycle_status"] == "active"
    assert body["epistemic_state"] == "observation"
    assert body["tenant_id"] is not None
    assert len(body["version_history"]) == 1
    assert response.headers["Location"] == f"{BASE}/{body['relationship_id']}"


async def test_observe_global_relationship_requires_platform_authority(
    owner_client: AsyncClient, platform_admin_client: AsyncClient
) -> None:
    """An organization OWNER holding every tenant Permission still
    cannot create a global relationship."""
    denied = await owner_client.post(f"{BASE}/observations/global", json=_observe_body())
    assert denied.status_code == 403

    allowed = await platform_admin_client.post(f"{BASE}/observations/global", json=_observe_body())
    assert allowed.status_code == 201
    assert allowed.json()["tenant_id"] is None


async def test_observe_tenant_relationship_requires_observe_permission(
    no_permission_client: AsyncClient,
) -> None:
    response = await no_permission_client.post(f"{BASE}/observations/tenant", json=_observe_body())
    assert response.status_code == 403


async def test_duplicate_observation_returns_409(owner_client: AsyncClient) -> None:
    body = _observe_body()
    assert (await owner_client.post(f"{BASE}/observations/tenant", json=body)).status_code == 201
    conflict = await owner_client.post(f"{BASE}/observations/tenant", json=body)
    assert conflict.status_code == 409


async def test_incompatible_endpoints_return_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json=_observe_body(
            source_entity={"entity_type": "campaign", "entity_id": "c1"},
            target_entity={"entity_type": "malware", "entity_id": "m1"},
        ),
    )
    assert response.status_code == 422


async def test_unknown_enum_value_returns_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant", json=_observe_body(relationship_type="not_a_type")
    )
    assert response.status_code == 422


async def test_unknown_ioc_endpoint_returns_422(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json=_observe_body(
            relationship_type="ioc_to_malware",
            source_entity={"entity_type": "ioc", "entity_id": str(uuid4())},
            target_entity={"entity_type": "malware", "entity_id": "m1"},
        ),
    )
    assert response.status_code == 422


async def test_observation_accepts_initial_evidence(owner_client: AsyncClient) -> None:
    body = await _create_tenant_relationship(
        owner_client,
        evidence_citations=["report-a", "report-b"],
        source_attributions=[_attribution("vendor")],
    )
    assert [c["value"] for c in body["evidence_citations"]] == ["report-a", "report-b"]
    assert body["source_attributions"][0]["source_system"] == "vendor"


# ── Reads and ownership-based authorization ──────────────────────────────


async def test_get_own_tenant_relationship(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.get(f"{BASE}/{created['relationship_id']}")
    assert response.status_code == 200
    assert response.json()["relationship_id"] == created["relationship_id"]


async def test_another_tenant_gets_404_not_403(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    """Cross-tenant access must be indistinguishable from 'does not
    exist' — never a 403, which would confirm the record's existence."""
    created = await _create_tenant_relationship(owner_client)
    response = await other_tenant_client.get(f"{BASE}/{created['relationship_id']}")
    assert response.status_code == 404


async def test_get_missing_relationship_returns_404(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(f"{BASE}/{uuid4()}")).status_code == 404


async def test_platform_admin_can_read_a_global_relationship(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _create_global_relationship(platform_admin_client)
    response = await platform_admin_client.get(f"{BASE}/{created['relationship_id']}")
    assert response.status_code == 200
    assert response.json()["tenant_id"] is None


async def test_tenant_caller_without_platform_authority_cannot_read_a_global_record(
    platform_admin_client: AsyncClient, owner_client: AsyncClient
) -> None:
    created = await _create_global_relationship(platform_admin_client)
    response = await owner_client.get(f"{BASE}/{created['relationship_id']}")
    assert response.status_code == 403


async def test_platform_admin_cannot_reach_a_tenant_record(
    owner_client: AsyncClient, platform_admin_client: AsyncClient
) -> None:
    """Platform authority governs GLOBAL records only — it is not a
    master key over tenant data."""
    created = await _create_tenant_relationship(owner_client)
    response = await platform_admin_client.get(f"{BASE}/{created['relationship_id']}")
    assert response.status_code == 404


async def test_list_tenant_relationships_is_scoped(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    await _create_tenant_relationship(owner_client)
    await _create_tenant_relationship(owner_client)

    mine = await owner_client.get(BASE)
    assert mine.status_code == 200
    assert mine.json()["count"] == 2

    theirs = await other_tenant_client.get(BASE)
    assert theirs.json()["count"] == 0


async def test_list_supports_filters_and_pagination(owner_client: AsyncClient) -> None:
    source_id = f"m-{uuid4()}"
    for _ in range(3):
        await _create_tenant_relationship(
            owner_client,
            source_entity={"entity_type": "malware", "entity_id": source_id},
        )
    filtered = await owner_client.get(BASE, params={"source_entity_id": source_id})
    assert filtered.json()["count"] == 3

    page = await owner_client.get(BASE, params={"limit": 2, "offset": 0})
    assert page.json()["count"] == 2
    assert page.json()["limit"] == 2


async def test_list_rejects_out_of_range_pagination(owner_client: AsyncClient) -> None:
    assert (await owner_client.get(BASE, params={"limit": 0})).status_code == 422
    assert (await owner_client.get(BASE, params={"limit": 10_000})).status_code == 422
    assert (await owner_client.get(BASE, params={"offset": -1})).status_code == 422


async def test_list_global_requires_platform_read(
    owner_client: AsyncClient, platform_admin_client: AsyncClient
) -> None:
    assert (await owner_client.get(f"{BASE}/global")).status_code == 403
    assert (await platform_admin_client.get(f"{BASE}/global")).status_code == 200


async def test_global_list_path_is_not_shadowed_by_the_id_route(
    platform_admin_client: AsyncClient,
) -> None:
    """`/global` must resolve to the list route, never be parsed as a
    `{relationship_id}`."""
    response = await platform_admin_client.get(f"{BASE}/global")
    assert response.status_code == 200
    assert "items" in response.json()


# ── Enrichment ───────────────────────────────────────────────────────────


async def test_add_evidence_citation(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['relationship_id']}/evidence-citations",
        json={"value": "report-x"},
    )
    assert response.status_code == 200
    body = response.json()
    assert [c["value"] for c in body["evidence_citations"]] == ["report-x"]
    assert len(body["version_history"]) == 2


async def test_add_source_attribution(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['relationship_id']}/source-attributions",
        json={"attribution": _attribution("vendor-y")},
    )
    assert response.status_code == 200
    assert response.json()["source_attributions"][0]["source_system"] == "vendor-y"


async def test_enrichment_across_tenants_returns_404(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await other_tenant_client.post(
        f"{BASE}/{created['relationship_id']}/evidence-citations", json={"value": "x"}
    )
    assert response.status_code == 404


async def test_empty_evidence_citation_returns_422(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['relationship_id']}/evidence-citations", json={"value": "  "}
    )
    assert response.status_code == 422


# ── Epistemic axis ───────────────────────────────────────────────────────


async def test_transition_epistemic_state(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{created['relationship_id']}/epistemic-state",
        json={"target_state": "evidence", "evidence": _attribution()},
    )
    assert response.status_code == 200
    assert response.json()["epistemic_state"] == "evidence"


async def test_illegal_epistemic_transition_returns_409(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{created['relationship_id']}/epistemic-state",
        json={"target_state": "validated", "evidence": _attribution()},
    )
    assert response.status_code == 409


async def test_unknown_epistemic_target_returns_422(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{created['relationship_id']}/epistemic-state",
        json={"target_state": "believed", "evidence": _attribution()},
    )
    assert response.status_code == 422


async def test_epistemic_walk_up_the_claim_hierarchy(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    rid = created["relationship_id"]
    for state in ("evidence", "hypothesis", "corroborated", "validated"):
        response = await owner_client.patch(
            f"{BASE}/{rid}/epistemic-state",
            json={"target_state": state, "evidence": _attribution()},
        )
        assert response.status_code == 200, response.text
        assert response.json()["epistemic_state"] == state


# ── Lifecycle axis ───────────────────────────────────────────────────────


async def test_lifecycle_deprecate_reactivate_revoke(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    rid = created["relationship_id"]

    deprecated = await owner_client.patch(
        f"{BASE}/{rid}/deprecate", json={"evidence": _attribution()}
    )
    assert deprecated.status_code == 200
    assert deprecated.json()["lifecycle_status"] == "deprecated"

    reactivated = await owner_client.patch(
        f"{BASE}/{rid}/reactivate", json={"evidence": _attribution()}
    )
    assert reactivated.json()["lifecycle_status"] == "active"

    revoked = await owner_client.patch(f"{BASE}/{rid}/revoke", json={"evidence": _attribution()})
    assert revoked.json()["lifecycle_status"] == "revoked"


async def test_illegal_lifecycle_transition_returns_409(owner_client: AsyncClient) -> None:
    created = await _create_tenant_relationship(owner_client)
    rid = created["relationship_id"]
    await owner_client.patch(f"{BASE}/{rid}/revoke", json={"evidence": _attribution()})
    conflict = await owner_client.patch(
        f"{BASE}/{rid}/deprecate", json={"evidence": _attribution()}
    )
    assert conflict.status_code == 409


async def test_supersede_records_the_successor(owner_client: AsyncClient) -> None:
    old = await _create_tenant_relationship(owner_client)
    new = await _create_tenant_relationship(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{old['relationship_id']}/supersede",
        json={"superseded_by": new["relationship_id"], "evidence": _attribution()},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["lifecycle_status"] == "superseded"
    assert body["superseded_by"] == new["relationship_id"]


async def test_platform_admin_can_manage_a_global_relationship(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _create_global_relationship(platform_admin_client)
    rid = created["relationship_id"]
    response = await platform_admin_client.patch(
        f"{BASE}/{rid}/deprecate", json={"evidence": _attribution()}
    )
    assert response.status_code == 200
    assert response.json()["lifecycle_status"] == "deprecated"


async def test_lifecycle_on_missing_relationship_returns_404(
    owner_client: AsyncClient,
) -> None:
    response = await owner_client.patch(
        f"{BASE}/{uuid4()}/revoke", json={"evidence": _attribution()}
    )
    assert response.status_code == 404


async def test_version_history_accumulates_across_requests(
    owner_client: AsyncClient,
) -> None:
    created = await _create_tenant_relationship(owner_client)
    rid = created["relationship_id"]
    await owner_client.post(f"{BASE}/{rid}/evidence-citations", json={"value": "c1"})
    await owner_client.patch(
        f"{BASE}/{rid}/epistemic-state",
        json={"target_state": "evidence", "evidence": _attribution()},
    )
    final = await owner_client.patch(f"{BASE}/{rid}/deprecate", json={"evidence": _attribution()})
    versions = [v["version"] for v in final.json()["version_history"]]
    assert versions == [1, 2, 3, 4]

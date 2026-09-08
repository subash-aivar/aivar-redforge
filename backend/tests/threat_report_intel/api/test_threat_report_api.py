"""End-to-end API tests for threat_report_intel over a real ASGI app
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

BASE = "/api/v1/threat-report-intel"
EVIDENCE = {
    "source_system": "redforge-analyst",
    "reference": "report-42",
    "observed_at": "2026-08-06T12:00:00+00:00",
    "confidence": "high",
}


def _title() -> str:
    return f"Operation Report {random.randint(1, 10**12)}"


def _payload(**overrides: object) -> dict:
    payload: dict = {
        "title": _title(),
        "publisher": {"organization_name": "Acme Threat Labs", "contact": "intel@acme.example"},
        "publication_date": "2026-07-01",
        "report_metadata": {
            "report_type": "advisory",
            "tlp_marking": "tlp_clear",
            "external_report_id": "ACME-2026-014",
        },
        "executive_summary": "Leadership-level impact summary.",
        "technical_summary": "Analyst-level mechanism and artefacts.",
        "severity": "high",
        "confidence": "high",
    }
    payload.update(overrides)
    return payload


async def _observe_tenant(client: AsyncClient, **body: object) -> dict:
    response = await client.post(f"{BASE}/observations/tenant", json=_payload(**body))
    assert response.status_code == 201, response.text
    return response.json()


async def _observe_global(client: AsyncClient, **body: object) -> dict:
    response = await client.post(f"{BASE}/observations/global", json=_payload(**body))
    assert response.status_code == 201, response.text
    return response.json()


# ── Observation ──────────────────────────────────────────────────────────


async def test_observe_tenant_report(owner_client: AsyncClient) -> None:
    title = _title()
    body = await _observe_tenant(owner_client, title=title)
    assert body["title"] == title
    assert body["canonical_title"] == title.lower()
    assert body["lifecycle_status"] == "active"
    assert body["publisher"]["organization_name"] == "Acme Threat Labs"
    assert body["report_metadata"]["tlp_marking"] == "tlp_clear"
    assert body["executive_summary"] != body["technical_summary"]
    assert body["tenant_id"] is not None


async def test_observe_sets_a_location_header(owner_client: AsyncClient) -> None:
    response = await owner_client.post(f"{BASE}/observations/tenant", json=_payload())
    assert response.status_code == 201
    assert response.headers["Location"].startswith(f"{BASE}/")


async def test_observe_rejects_a_duplicate_canonical_title(owner_client: AsyncClient) -> None:
    title = _title()
    await _observe_tenant(owner_client, title=title)
    response = await owner_client.post(
        f"{BASE}/observations/tenant", json=_payload(title=title.upper())
    )
    assert response.status_code == 409, response.text


async def test_observe_rejects_a_blank_title(owner_client: AsyncClient) -> None:
    response = await owner_client.post(f"{BASE}/observations/tenant", json=_payload(title="  -_ "))
    assert response.status_code == 422, response.text


async def test_observe_rejects_an_unknown_tlp_marking(owner_client: AsyncClient) -> None:
    response = await owner_client.post(
        f"{BASE}/observations/tenant",
        json=_payload(report_metadata={"report_type": "advisory", "tlp_marking": "tlp_purple"}),
    )
    assert response.status_code == 422, response.text


async def test_report_type_is_free_text_and_accepted(owner_client: AsyncClient) -> None:
    body = await _observe_tenant(
        owner_client,
        report_metadata={"report_type": "quarterly-horizon-scan", "tlp_marking": "tlp_green"},
    )
    assert body["report_metadata"]["report_type"] == "quarterly-horizon-scan"


async def test_a_tenant_caller_cannot_observe_globally(owner_client: AsyncClient) -> None:
    response = await owner_client.post(f"{BASE}/observations/global", json=_payload())
    assert response.status_code == 403, response.text


async def test_a_platform_caller_can_observe_globally(platform_admin_client: AsyncClient) -> None:
    body = await _observe_global(platform_admin_client)
    assert body["tenant_id"] is None


async def test_a_caller_without_permission_is_forbidden(no_permission_client: AsyncClient) -> None:
    response = await no_permission_client.post(f"{BASE}/observations/tenant", json=_payload())
    assert response.status_code == 403, response.text


# ── Reads ────────────────────────────────────────────────────────────────


async def test_get_returns_the_detail(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.get(f"{BASE}/{created['threat_report_id']}")
    assert response.status_code == 200, response.text
    assert response.json()["threat_report_id"] == created["threat_report_id"]


async def test_a_foreign_tenant_gets_404_not_403(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.get(f"{BASE}/{created['threat_report_id']}")
    assert response.status_code == 404, response.text


async def test_get_of_an_unknown_id_is_404(owner_client: AsyncClient) -> None:
    response = await owner_client.get(f"{BASE}/00000000-0000-4000-8000-000000000001")
    assert response.status_code == 404, response.text


async def test_get_of_a_malformed_id_is_422(owner_client: AsyncClient) -> None:
    response = await owner_client.get(f"{BASE}/not-a-uuid")
    assert response.status_code == 422, response.text


async def test_a_platform_caller_reads_a_global_record_without_tenant_permission(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await platform_admin_client.get(f"{BASE}/{created['threat_report_id']}")
    assert response.status_code == 200, response.text


async def test_list_tenant_reports_is_paginated_and_filterable(owner_client: AsyncClient) -> None:
    await _observe_tenant(owner_client, severity="critical")
    await _observe_tenant(owner_client, severity="low")

    response = await owner_client.get(f"{BASE}", params={"limit": 1})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["count"] == 1
    assert body["limit"] == 1

    response = await owner_client.get(f"{BASE}", params={"severity": "critical"})
    assert all(i["severity"] == "critical" for i in response.json()["items"])

    response = await owner_client.get(f"{BASE}", params={"lifecycle_status": "active"})
    assert all(i["lifecycle_status"] == "active" for i in response.json()["items"])

    response = await owner_client.get(f"{BASE}", params={"tlp_marking": "tlp_clear"})
    assert all(i["tlp_marking"] == "tlp_clear" for i in response.json()["items"])


async def test_list_rejects_an_out_of_range_limit(owner_client: AsyncClient) -> None:
    response = await owner_client.get(f"{BASE}", params={"limit": 5000})
    assert response.status_code == 422


async def test_list_global_requires_platform_authority(
    owner_client: AsyncClient, platform_admin_client: AsyncClient
) -> None:
    assert (await owner_client.get(f"{BASE}/global")).status_code == 403
    assert (await platform_admin_client.get(f"{BASE}/global")).status_code == 200


# ── Enrichment ───────────────────────────────────────────────────────────


async def test_add_reference(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['threat_report_id']}/references",
        json={"reference": {"url_or_citation": "https://example.test/a", "description": "mirror"}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["references"][0]["url_or_citation"] == "https://example.test/a"
    assert body["references"][0]["description"] == "mirror"


async def test_add_reference_rejects_an_empty_citation(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['threat_report_id']}/references",
        json={"reference": {"url_or_citation": "  "}},
    )
    assert response.status_code == 422, response.text


async def test_add_evidence_citation(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['threat_report_id']}/evidence-citations",
        json={"citation": "peer review note"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["evidence_citations"] == ["peer review note"]


async def test_add_source_attribution(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    response = await owner_client.post(
        f"{BASE}/{created['threat_report_id']}/source-attributions",
        json={"attribution": EVIDENCE},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source_attributions"][0]["source_system"] == "redforge-analyst"
    assert len(body["version_history"]) == 2


async def test_enrichment_across_tenants_is_404(
    owner_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await other_tenant_client.post(
        f"{BASE}/{created['threat_report_id']}/evidence-citations", json={"citation": "x"}
    )
    assert response.status_code == 404, response.text


async def test_a_platform_caller_cannot_mutate_a_tenant_record(
    owner_client: AsyncClient, platform_admin_client: AsyncClient
) -> None:
    created = await _observe_tenant(owner_client)
    response = await platform_admin_client.post(
        f"{BASE}/{created['threat_report_id']}/evidence-citations", json={"citation": "x"}
    )
    assert response.status_code == 404, response.text


# ── Record lifecycle ─────────────────────────────────────────────────────


async def test_deprecate_then_reactivate(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    rid = created["threat_report_id"]

    response = await owner_client.patch(f"{BASE}/{rid}/deprecate", json={"evidence": EVIDENCE})
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle_status"] == "deprecated"

    response = await owner_client.patch(f"{BASE}/{rid}/reactivate", json={"evidence": EVIDENCE})
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle_status"] == "active"


async def test_revoke_is_terminal(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    rid = created["threat_report_id"]
    response = await owner_client.patch(f"{BASE}/{rid}/revoke", json={"evidence": EVIDENCE})
    assert response.status_code == 200, response.text
    response = await owner_client.patch(f"{BASE}/{rid}/reactivate", json={"evidence": EVIDENCE})
    assert response.status_code == 409, response.text


async def test_supersede(owner_client: AsyncClient) -> None:
    created = await _observe_tenant(owner_client)
    successor = await _observe_tenant(owner_client)
    response = await owner_client.patch(
        f"{BASE}/{created['threat_report_id']}/supersede",
        json={"superseded_by": successor["threat_report_id"], "evidence": EVIDENCE},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["lifecycle_status"] == "superseded"
    assert body["superseded_by"] == successor["threat_report_id"]


async def test_a_platform_caller_manages_a_global_record(
    platform_admin_client: AsyncClient,
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await platform_admin_client.patch(
        f"{BASE}/{created['threat_report_id']}/deprecate", json={"evidence": EVIDENCE}
    )
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle_status"] == "deprecated"


async def test_a_tenant_caller_cannot_manage_a_global_record(
    platform_admin_client: AsyncClient, owner_client: AsyncClient
) -> None:
    created = await _observe_global(platform_admin_client)
    response = await owner_client.patch(
        f"{BASE}/{created['threat_report_id']}/deprecate", json={"evidence": EVIDENCE}
    )
    assert response.status_code == 403, response.text

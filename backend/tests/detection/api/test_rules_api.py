"""Detection rule API tests using in-memory fake UoW (no Postgres)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient

from detection.domain.value_objects.enums import RuleLifecycleState
from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId


def _logic() -> dict:
    return {
        "logic_type": "Condition",
        "conditions": [
            {
                "field": "process.name",
                "operator": "eq",
                "value": "cmd.exe",
            }
        ],
    }


def _author_payload(*, key_suffix: str = "1", with_throttle: bool = False) -> dict:
    payload: dict = {
        "rule_key": f"aivar.api_rule_{key_suffix}",
        "title": "API test rule",
        "description": "created via API",
        "category": "Threat",
        "severity": "High",
        "confidence": "Medium",
        "logic": _logic(),
        "tags": ["endpoint"],
        "test_cases": [
            {
                "name": "positive",
                "input_payload": {"process.name": "cmd.exe"},
                "expected_match": True,
            }
        ],
    }
    if with_throttle:
        payload["throttle"] = {"window_seconds": 60, "max_count": 5}
    return payload


@pytest.mark.asyncio
async def test_author_detection_rule_201(async_client: AsyncClient) -> None:
    resp = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="create")
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["lifecycle_state"] == "Draft"
    assert body["severity"] == "High"
    assert "Location" in resp.headers
    assert "/api/v1/detection-rules/" in resp.headers["Location"]


@pytest.mark.asyncio
async def test_get_detection_rule_200(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="get")
    )
    assert created.status_code == 201
    rid = created.json()["rule_id"]
    resp = await async_client.get(f"/api/v1/detection-rules/{rid}")
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == rid


@pytest.mark.asyncio
async def test_list_detection_rules_200(async_client: AsyncClient) -> None:
    await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="list1")
    )
    await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="list2")
    )
    resp = await async_client.get("/api/v1/detection-rules")
    assert resp.status_code == 200
    assert resp.json()["total"] >= 2


@pytest.mark.asyncio
async def test_patch_detection_rule_200(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="patch")
    )
    rid = created.json()["rule_id"]
    resp = await async_client.patch(
        f"/api/v1/detection-rules/{rid}",
        json={"title": "Patched title", "severity": "Critical"},
    )
    assert resp.status_code == 200
    assert resp.json()["title"] == "Patched title"
    assert resp.json()["severity"] == "Critical"


@pytest.mark.asyncio
async def test_publish_rule_version_200(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="pub")
    )
    rid = created.json()["rule_id"]
    resp = await async_client.post(
        f"/api/v1/detection-rules/{rid}/publish",
        json={"change_summary": "initial release", "semver": "1.0.0"},
    )
    assert resp.status_code == 200
    assert len(resp.json()["versions"]) == 1
    assert resp.json()["versions"][0]["semver"] == "1.0.0"


@pytest.mark.asyncio
async def test_promote_to_under_review_200(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="promo")
    )
    rid = created.json()["rule_id"]
    resp = await async_client.post(
        f"/api/v1/detection-rules/{rid}/promote",
        json={"target_state": "UnderReview"},
    )
    assert resp.status_code == 200
    assert resp.json()["lifecycle_state"] == "UnderReview"


@pytest.mark.asyncio
async def test_promote_to_tested_after_suite_200(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="tested")
    )
    rid = created.json()["rule_id"]
    await async_client.post(
        f"/api/v1/detection-rules/{rid}/promote",
        json={"target_state": "UnderReview"},
    )
    suite = await async_client.post(f"/api/v1/detection-rules/{rid}/test-suite")
    assert suite.status_code == 200
    assert suite.json()["results"][0]["status"] == "Pass"
    resp = await async_client.post(
        f"/api/v1/detection-rules/{rid}/promote",
        json={"target_state": "Tested"},
    )
    assert resp.status_code == 200
    assert resp.json()["lifecycle_state"] == "Tested"


@pytest.mark.asyncio
async def test_demote_active_to_staged_200(async_client: AsyncClient, app) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules",
        json=_author_payload(key_suffix="demote", with_throttle=True),
    )
    rid = created.json()["rule_id"]
    await async_client.post(
        f"/api/v1/detection-rules/{rid}/publish",
        json={"change_summary": "v1", "semver": "1.0.0"},
    )
    # Force Active for demotion path
    from uuid import UUID

    org_id = UUID(created.json()["tenant_id"])
    repo = app.state.rule_repo
    agg = await repo.find_by_id(DetectionRuleId(UUID(rid)), TenantId(org_id))
    assert agg is not None
    agg.lifecycle_state = RuleLifecycleState.ACTIVE
    await repo.save(agg)

    resp = await async_client.post(
        f"/api/v1/detection-rules/{rid}/demote",
        json={"target_state": "Staged", "reason": "hotfix"},
    )
    assert resp.status_code == 200
    assert resp.json()["lifecycle_state"] == "Staged"


@pytest.mark.asyncio
async def test_validate_rule_200(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="val")
    )
    rid = created.json()["rule_id"]
    resp = await async_client.post(f"/api/v1/detection-rules/{rid}/validate")
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


@pytest.mark.asyncio
async def test_get_unknown_rule_404(async_client: AsyncClient) -> None:
    resp = await async_client.get(f"/api/v1/detection-rules/{uuid4()}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_rule_key_409(async_client: AsyncClient) -> None:
    payload = _author_payload(key_suffix="dup")
    first = await async_client.post("/api/v1/detection-rules", json=payload)
    assert first.status_code == 201
    second = await async_client.post("/api/v1/detection-rules", json=payload)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_cross_tenant_get_returns_404(
    async_client: AsyncClient,
    other_tenant_client: AsyncClient,
) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="xtenant")
    )
    assert created.status_code == 201
    rid = created.json()["rule_id"]
    resp = await other_tenant_client.get(f"/api/v1/detection-rules/{rid}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_invalid_rule_key_422(async_client: AsyncClient) -> None:
    payload = _author_payload(key_suffix="bad")
    payload["rule_key"] = "NOT VALID"
    resp = await async_client.post("/api/v1/detection-rules", json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_promote_invalid_skip_422(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="skip")
    )
    rid = created.json()["rule_id"]
    resp = await async_client.post(
        f"/api/v1/detection-rules/{rid}/promote",
        json={"target_state": "Active"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_filter_by_lifecycle(async_client: AsyncClient) -> None:
    created = await async_client.post(
        "/api/v1/detection-rules", json=_author_payload(key_suffix="filt")
    )
    rid = created.json()["rule_id"]
    await async_client.post(
        f"/api/v1/detection-rules/{rid}/promote",
        json={"target_state": "UnderReview"},
    )
    resp = await async_client.get(
        "/api/v1/detection-rules", params={"lifecycle_state": "UnderReview"}
    )
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1
    assert all(i["lifecycle_state"] == "UnderReview" for i in resp.json()["items"])

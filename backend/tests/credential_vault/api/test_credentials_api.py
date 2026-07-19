"""API integration tests for credential vault credentials endpoints."""

from __future__ import annotations

import base64
from uuid import uuid4

import pytest
from httpx import AsyncClient

from credential_vault.infrastructure.persistence.repositories.pg_audit_log_repository import (
    PgAuditLogRepository,
)

pytestmark = pytest.mark.integration


async def _register_backend(client: AsyncClient, name: str | None = None) -> str:
    response = await client.post(
        "/api/v1/vault-backends",
        json={
            "name": name or f"backend-{uuid4().hex[:8]}",
            "backend_type": "LOCAL_ENCRYPTED",
            "config": {"region": "us-east-1"},
            "is_default": True,
        },
    )
    assert response.status_code == 201
    return response.json()["backend_id"]


async def _create_credential(
    client: AsyncClient,
    backend_id: str,
    *,
    name: str | None = None,
    secret: str = "super-secret-value",
) -> dict[str, object]:
    credential_name = name or f"cred-{uuid4().hex[:8]}"
    response = await client.post(
        "/api/v1/credentials",
        json={
            "name": credential_name,
            "category": "API_KEY",
            "subtype": "OPENAI",
            "vault_backend_id": backend_id,
            "plaintext_secret": secret,
            "description": "api test credential",
            "tags": {"source": "test"},
        },
    )
    assert response.status_code == 201
    return response.json()


@pytest.mark.asyncio
async def test_create_credential_returns_201_with_location_header(
    async_client: AsyncClient,
) -> None:
    backend_id = await _register_backend(async_client)
    response = await async_client.post(
        "/api/v1/credentials",
        json={
            "name": f"located-{uuid4().hex[:8]}",
            "category": "API_KEY",
            "subtype": "OPENAI",
            "vault_backend_id": backend_id,
            "plaintext_secret": "located-secret",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert response.headers["location"] == f"/api/v1/credentials/{body['credential_id']}"


@pytest.mark.asyncio
async def test_create_credential_duplicate_name_returns_409(async_client: AsyncClient) -> None:
    backend_id = await _register_backend(async_client)
    name = f"duplicate-{uuid4().hex[:8]}"
    first = await async_client.post(
        "/api/v1/credentials",
        json={
            "name": name,
            "category": "API_KEY",
            "subtype": "OPENAI",
            "vault_backend_id": backend_id,
            "plaintext_secret": "first-secret",
        },
    )
    assert first.status_code == 201
    second = await async_client.post(
        "/api/v1/credentials",
        json={
            "name": name,
            "category": "API_KEY",
            "subtype": "OPENAI",
            "vault_backend_id": backend_id,
            "plaintext_secret": "second-secret",
        },
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_get_credential_not_found_returns_404(async_client: AsyncClient) -> None:
    missing_id = uuid4()
    response = await async_client.get(f"/api/v1/credentials/{missing_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_credential_wrong_tenant_returns_404(
    async_client: AsyncClient,
    other_tenant_client: AsyncClient,
) -> None:
    backend_id = await _register_backend(async_client)
    created = await _create_credential(async_client, backend_id)
    credential_id = created["credential_id"]
    response = await other_tenant_client.get(f"/api/v1/credentials/{credential_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_resolve_credential_returns_base64_secret(async_client: AsyncClient) -> None:
    backend_id = await _register_backend(async_client)
    created = await _create_credential(async_client, backend_id, secret="resolve-me-please")
    credential_id = created["credential_id"]
    response = await async_client.post(
        f"/api/v1/credentials/{credential_id}/resolve",
        json={"purpose": "integration-test"},
    )
    assert response.status_code == 200
    body = response.json()
    assert base64.b64decode(body["secret_b64"]).decode() == "resolve-me-please"


@pytest.mark.asyncio
async def test_resolve_credential_audit_fail_returns_500(
    async_client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend_id = await _register_backend(async_client)
    created = await _create_credential(async_client, backend_id, secret="audit-fail-secret")
    credential_id = created["credential_id"]

    async def _fail_append(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(PgAuditLogRepository, "append_entry", _fail_append)

    response = await async_client.post(
        f"/api/v1/credentials/{credential_id}/resolve",
        json={"purpose": "integration-test"},
    )
    assert response.status_code == 500


@pytest.mark.asyncio
async def test_rotate_commit_abort_lifecycle(async_client: AsyncClient) -> None:
    backend_id = await _register_backend(async_client)
    created = await _create_credential(async_client, backend_id, secret="rotate-v1")
    credential_id = created["credential_id"]

    rotate = await async_client.post(
        f"/api/v1/credentials/{credential_id}/rotate",
        json={"new_plaintext_secret": "rotate-v2-pending"},
    )
    assert rotate.status_code == 200
    assert rotate.json()["state"] == "ROTATING"

    abort = await async_client.post(f"/api/v1/credentials/{credential_id}/abort-rotation")
    assert abort.status_code == 200
    assert abort.json()["state"] == "ACTIVE"

    rotate_again = await async_client.post(
        f"/api/v1/credentials/{credential_id}/rotate",
        json={"new_plaintext_secret": "rotate-v2-final"},
    )
    assert rotate_again.status_code == 200

    commit = await async_client.post(f"/api/v1/credentials/{credential_id}/commit-rotation")
    assert commit.status_code == 200
    assert commit.json()["state"] == "ACTIVE"

    resolve = await async_client.post(
        f"/api/v1/credentials/{credential_id}/resolve",
        json={"purpose": "post-rotation-check"},
    )
    assert resolve.status_code == 200
    assert base64.b64decode(resolve.json()["secret_b64"]).decode() == "rotate-v2-final"


@pytest.mark.asyncio
async def test_list_credentials_empty_list_returns_200(async_client: AsyncClient) -> None:
    response = await async_client.get("/api/v1/credentials")
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    assert body["total"] == 0


@pytest.mark.asyncio
async def test_list_credentials_state_filter(async_client: AsyncClient) -> None:
    backend_id = await _register_backend(async_client)
    active = await _create_credential(async_client, backend_id, name=f"active-{uuid4().hex[:8]}")
    disabled_cred = await _create_credential(
        async_client, backend_id, name=f"disabled-{uuid4().hex[:8]}"
    )
    disable = await async_client.post(
        f"/api/v1/credentials/{disabled_cred['credential_id']}/disable",
        json={"reason": "maintenance"},
    )
    assert disable.status_code == 200

    active_list = await async_client.get("/api/v1/credentials", params={"states": ["ACTIVE"]})
    assert active_list.status_code == 200
    active_ids = {item["credential_id"] for item in active_list.json()["items"]}
    assert active["credential_id"] in active_ids
    assert disabled_cred["credential_id"] not in active_ids

    disabled_list = await async_client.get("/api/v1/credentials", params={"states": ["DISABLED"]})
    assert disabled_list.status_code == 200
    disabled_ids = {item["credential_id"] for item in disabled_list.json()["items"]}
    assert disabled_cred["credential_id"] in disabled_ids


@pytest.mark.asyncio
async def test_hard_delete_returns_204(async_client: AsyncClient) -> None:
    backend_id = await _register_backend(async_client)
    created = await _create_credential(async_client, backend_id)
    credential_id = created["credential_id"]
    revoke = await async_client.post(
        f"/api/v1/credentials/{credential_id}/revoke",
        json={"reason": "retire credential"},
    )
    assert revoke.status_code == 200

    delete = await async_client.delete(f"/api/v1/credentials/{credential_id}")
    assert delete.status_code == 204

    get_after = await async_client.get(f"/api/v1/credentials/{credential_id}")
    assert get_after.status_code == 410


@pytest.mark.asyncio
async def test_revoke_then_emergency_revoke_returns_200(async_client: AsyncClient) -> None:
    backend_id = await _register_backend(async_client)
    created = await _create_credential(async_client, backend_id)
    credential_id = created["credential_id"]

    revoke = await async_client.post(
        f"/api/v1/credentials/{credential_id}/revoke",
        json={"reason": "standard revoke"},
    )
    assert revoke.status_code == 200
    assert revoke.json()["state"] == "REVOKED"

    emergency = await async_client.post(
        f"/api/v1/credentials/{credential_id}/emergency-revoke",
        json={"justification": "incident response"},
    )
    assert emergency.status_code == 200
    assert emergency.json()["state"] == "REVOKED"

"""API integration tests for authentication endpoints."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.api.dependencies import get_auth_service
from redforge.api.v1.auth import router
from redforge.application.auth import AuthService
from redforge.infrastructure.auth.password import Argon2PasswordHasher
from redforge.infrastructure.auth.tokens import JWTTokenService
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models import UserModel  # noqa: F401
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


@pytest.fixture
async def app() -> FastAPI:
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    events = InMemoryEventPublisher()
    hasher = Argon2PasswordHasher(time_cost=1, memory_cost=16384, parallelism=1)
    tokens = JWTTokenService(secret_key="test-secret-key-that-is-long-enough-32!", access_ttl=3600)
    service = AuthService(factory, hasher, tokens, events)

    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")
    test_app.add_middleware(ErrorHandlerMiddleware)
    test_app.dependency_overrides[get_auth_service] = lambda: service

    yield test_app
    await engine.dispose()


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _register(client: AsyncClient, email: str = "user@test.com") -> dict:
    resp = await client.post("/api/v1/auth/register", json={
        "email": email,
        "display_name": "Test User",
        "password": "SecureP@ss123",
    })
    return resp.json()


class TestRegister:
    async def test_registers_successfully(self, client: AsyncClient) -> None:
        resp = await client.post("/api/v1/auth/register", json={
            "email": "new@test.com",
            "display_name": "New User",
            "password": "SecureP@ss123",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "new@test.com"
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "Bearer"

    async def test_duplicate_email_returns_409(self, client: AsyncClient) -> None:
        await _register(client, "dup@test.com")
        resp = await client.post("/api/v1/auth/register", json={
            "email": "dup@test.com",
            "display_name": "Dup",
            "password": "SecureP@ss123",
        })
        assert resp.status_code == 409


class TestLogin:
    async def test_login_success(self, client: AsyncClient) -> None:
        await _register(client, "login@test.com")
        resp = await client.post("/api/v1/auth/login", json={
            "email": "login@test.com",
            "password": "SecureP@ss123",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_login_wrong_password(self, client: AsyncClient) -> None:
        await _register(client, "wrong@test.com")
        resp = await client.post("/api/v1/auth/login", json={
            "email": "wrong@test.com",
            "password": "WrongPassword",
        })
        assert resp.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient) -> None:
        resp = await client.post("/api/v1/auth/login", json={
            "email": "nobody@test.com",
            "password": "whatever",
        })
        assert resp.status_code == 401


class TestRefresh:
    async def test_refresh_success(self, client: AsyncClient) -> None:
        data = await _register(client, "refresh@test.com")
        resp = await client.post("/api/v1/auth/refresh", json={
            "refresh_token": data["refresh_token"],
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()


class TestMe:
    async def test_me_with_valid_token(self, client: AsyncClient) -> None:
        data = await _register(client, "me@test.com")
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "me@test.com"

    async def test_me_without_token_returns_401(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

"""Shared test fixtures for the AIVAR RedForge backend test suite.

Provides a configured test client and test settings that override
production values with safe test defaults.
"""

from collections.abc import AsyncGenerator
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from redforge.app import create_app
from redforge.core.config import Settings


@pytest.fixture
def test_settings() -> Settings:
    """Settings configured for the test environment."""
    return Settings(
        app_name="AIVAR RedForge Test",
        debug=True,
        environment="test",
        database_url="postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
        log_level="DEBUG",
        log_format="console",
    )


@pytest.fixture
async def client(test_settings: Settings) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client with lifespan events.

    Patches the database engine creation to use a mock since tests
    may not have a live database available. Tests requiring a real
    database connection should use a separate fixture.
    """
    with patch("redforge.app.create_engine"), patch("redforge.app.dispose_engine"):
        app = create_app(settings=test_settings)
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

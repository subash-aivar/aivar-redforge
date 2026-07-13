"""Async database session management.

Provides an async session factory and a dependency-injection-compatible
generator for use in FastAPI route handlers.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redforge.infrastructure.database.engine import get_engine


def create_session_factory() -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to the current engine.

    Returns:
        An async_sessionmaker configured with appropriate defaults.
    """
    return async_sessionmaker(
        bind=get_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session for dependency injection.

    The session is automatically closed when the request completes.
    This function is designed to be used with FastAPI's Depends().
    """
    factory = create_session_factory()
    async with factory() as session:
        yield session

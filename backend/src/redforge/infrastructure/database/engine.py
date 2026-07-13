"""Async SQLAlchemy engine lifecycle management.

Provides a module-level engine that is created at application startup
and disposed at shutdown. The engine manages the connection pool.
"""

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

_engine: AsyncEngine | None = None


def create_engine(database_url: str, echo: bool = False, pool_size: int = 10) -> AsyncEngine:
    """Create the async engine and store it at module level.

    Args:
        database_url: PostgreSQL async connection string.
        echo: If True, log all SQL statements (development only).
        pool_size: Maximum number of connections in the pool.

    Returns:
        The created AsyncEngine instance.
    """
    global _engine
    _engine = create_async_engine(
        database_url,
        echo=echo,
        pool_size=pool_size,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    return _engine


def get_engine() -> AsyncEngine:
    """Retrieve the current engine instance.

    Raises:
        RuntimeError: If the engine has not been created yet.
    """
    if _engine is None:
        raise RuntimeError(
            "Database engine not initialized. Call create_engine() during application startup."
        )
    return _engine


async def dispose_engine() -> None:
    """Dispose the engine and close all pooled connections.

    Safe to call even if the engine was never created.
    """
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None

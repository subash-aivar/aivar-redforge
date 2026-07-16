"""Startup configuration and connectivity validator — Sprint 28.

Runs before the application accepts traffic. Fails fast with clear error
messages so operators know exactly what to fix before the process starts.

Design rules:
- validate_startup() is called in the FastAPI lifespan BEFORE yielding.
- Database connectivity check is skipped when environment == "test" so that
  unit and API tests can run without a live database.
- Configuration validation always runs (no environment exemption).
- All failures are collected before raising so operators see every problem
  at once rather than one error per restart.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from redforge.core.config import Settings


class StartupValidationError(RuntimeError):
    """Raised when startup conditions are not met.

    Contains a human-readable summary of all validation failures so the
    operator can fix all problems in one restart cycle.
    """


async def validate_startup(settings: Settings, engine: AsyncEngine) -> None:
    """Validate database connectivity and configuration at startup.

    Raises:
        StartupValidationError: if any validation fails.
    """
    errors: list[str] = []

    _validate_config(settings, errors)

    if settings.environment != "test":
        await _check_database_connectivity(engine, errors)
        if not errors:
            # Only check migrations when DB is reachable
            await _check_migration_head(engine, errors)

    if errors:
        raise StartupValidationError(
            "Startup validation failed — fix the following before starting:\n"
            + "\n".join(f"  [{i + 1}] {e}" for i, e in enumerate(errors))
        )


def _validate_config(settings: Settings, errors: list[str]) -> None:
    if settings.runtime_replay_poll_interval_s <= 0:
        errors.append(
            f"runtime_replay_poll_interval_s must be > 0 "
            f"(got {settings.runtime_replay_poll_interval_s})"
        )

    if settings.runtime_replay_max_concurrent < 1:
        errors.append(
            f"runtime_replay_max_concurrent must be >= 1 "
            f"(got {settings.runtime_replay_max_concurrent})"
        )

    if settings.runtime_replay_batch_size < 1:
        errors.append(
            f"runtime_replay_batch_size must be >= 1 "
            f"(got {settings.runtime_replay_batch_size})"
        )

    if settings.runtime_dlq_poison_threshold < 1:
        errors.append(
            f"runtime_dlq_poison_threshold must be >= 1 "
            f"(got {settings.runtime_dlq_poison_threshold})"
        )


_EXPECTED_MIGRATION_HEAD = "0035"


async def _check_database_connectivity(engine: AsyncEngine, errors: list[str]) -> None:
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        errors.append(f"Database unreachable: {type(exc).__name__}: {exc}")
    except Exception as exc:
        errors.append(f"Database connectivity check failed: {type(exc).__name__}: {exc}")


async def _check_migration_head(engine: AsyncEngine, errors: list[str]) -> None:
    """Verify the Alembic migration head matches the expected revision."""
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError

    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT version_num FROM alembic_version")
            )
            row = result.fetchone()
        if row is None:
            errors.append(
                "alembic_version table is empty — run 'alembic upgrade head' before starting"
            )
        elif row[0] != _EXPECTED_MIGRATION_HEAD:
            errors.append(
                f"Database migration '{row[0]}' does not match expected head "
                f"'{_EXPECTED_MIGRATION_HEAD}' — run 'alembic upgrade head'"
            )
    except SQLAlchemyError as exc:
        errors.append(f"Migration check failed: {type(exc).__name__}: {exc}")
    except Exception as exc:
        errors.append(f"Migration check failed unexpectedly: {type(exc).__name__}: {exc}")

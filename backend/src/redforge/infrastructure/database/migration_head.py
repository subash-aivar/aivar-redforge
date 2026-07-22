"""Resolve the expected Alembic migration head from the script directory.

Startup and platform-validation checks need to know "what migration head
should this database be at". A literal string constant goes stale on every
new migration and silently turns into a false-positive outage the next time
someone forgets to bump it — that happened three times independently before
this helper existed (0053, 0070, and a third copy of 0053 all drifted behind
the real head once M29+ migrations landed). Reading it from the script
directory means it can never drift: it always reflects the migrations that
actually ship with this build.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def get_expected_migration_head() -> str:
    """Return the single head revision of the project's Alembic chain."""
    from alembic.script import ScriptDirectory

    migrations_dir = Path(__file__).resolve().parent / "migrations"
    script = ScriptDirectory(str(migrations_dir))
    head = script.get_current_head()
    if head is None:
        raise RuntimeError(f"no migration head found under {migrations_dir}")
    return head

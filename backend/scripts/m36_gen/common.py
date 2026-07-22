"""Shared helpers for M36 code generation."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
MIG = SRC / "redforge" / "infrastructure" / "database" / "migrations" / "versions"


def w(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if content.endswith("\n") else content + "\n"
    path.write_text(text)


def empty_inits(*paths: Path) -> None:
    for p in paths:
        w(p / "__init__.py", "")


def mig(rev: str, down: str, name: str, upgrade: str, downgrade: str) -> None:
    w(
        MIG / f"{rev}_{name}.py",
        f'''"""{rev} — M36 migration.

Migration chain: {down} → {rev}.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "{rev}"
down_revision: str = "{down}"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
{upgrade}

def downgrade() -> None:
{downgrade}
''',
    )

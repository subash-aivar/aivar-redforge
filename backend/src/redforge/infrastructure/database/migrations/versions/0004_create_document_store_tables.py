"""Create document-store tables for bounded context repositories.

These tables store JSON documents with a string primary key.
Used by: validation_runs, findings, evidence, attack_definitions,
         validation_policies, providers, payload_templates.

Using JSONB for efficient querying on PostgreSQL.

Revision ID: 0004
Revises: 0003
Create Date: 2025-02-01 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Tables that use the (id TEXT PK, data JSONB) pattern
_DOCUMENT_TABLES = [
    "validation_runs",
    "findings",
    "evidence",
    "attack_definitions",
    "validation_policies",
    "providers",
    "payload_templates",
]


def upgrade() -> None:
    for table_name in _DOCUMENT_TABLES:
        op.create_table(
            table_name,
            sa.Column("id", sa.String(26), nullable=False),
            sa.Column(
                "data",
                sa.JSON().with_variant(
                    sa.dialects.postgresql.JSONB, "postgresql"
                ),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id", name=f"pk_{table_name}"),
        )


def downgrade() -> None:
    for table_name in reversed(_DOCUMENT_TABLES):
        op.drop_table(table_name)

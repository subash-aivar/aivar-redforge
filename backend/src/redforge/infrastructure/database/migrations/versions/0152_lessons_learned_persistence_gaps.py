"""lessons_learned schema was missing columns/tables its own aggregates need.

Three gaps found while wiring PostgreSQL persistence for this bounded
context (LessonsLearnedContainer had been in-memory-only until now):

- lessons_learned_records had no created_at column, even though
  LessonsLearned.__init__ requires a non-null created_at.
- LessonsLearned.recommendations (list[Recommendation]) had no table at
  all — migration 0111 covered lessons and action items but not
  recommendations.
- post_incident_reports had no artifact_bytes column — PostIncidentReport
  holds the actual generated report payload in artifact_bytes: bytes,
  separate from artifact_ref (a pointer/URL). Only the ref had a column.

Migration chain: 0151 -> 0152.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0152"
down_revision: str = "0151"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "lessons_learned_records",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        schema="lessons_learned",
    )
    op.execute(
        "UPDATE lessons_learned.lessons_learned_records SET created_at = NOW() "
        "WHERE created_at IS NULL"
    )
    op.alter_column(
        "lessons_learned_records",
        "created_at",
        nullable=False,
        schema="lessons_learned",
    )

    op.create_table(
        "recommendations",
        sa.Column("recommendation_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ll_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("technique_ids", postgresql.JSONB(), nullable=False),
        schema="lessons_learned",
    )
    op.create_index(
        "ix_recommendations_ll", "recommendations", ["ll_id"], schema="lessons_learned"
    )

    op.add_column(
        "post_incident_reports",
        sa.Column("artifact_bytes", postgresql.BYTEA(), nullable=True),
        schema="lessons_learned",
    )


def downgrade() -> None:
    op.drop_column("post_incident_reports", "artifact_bytes", schema="lessons_learned")
    op.drop_index("ix_recommendations_ll", table_name="recommendations", schema="lessons_learned")
    op.drop_table("recommendations", schema="lessons_learned")
    op.drop_column("lessons_learned_records", "created_at", schema="lessons_learned")

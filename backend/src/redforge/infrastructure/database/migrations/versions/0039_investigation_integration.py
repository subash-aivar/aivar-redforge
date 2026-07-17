"""Investigation Integration — M22 Phase 6.

Schema additions:
  1. threat_intel_sync_state — durable sync job status for ATT&CK /
     vulnerability / indicator-refresh workers.
  2. investigation_path_compute_state — debounce bookkeeping for
     attack-path recomputation linked to investigations.
  3. attack_paths.investigation_id — optional tenant-scoped link from a
     computed path to the investigation that triggered it.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0039"
down_revision: str = "0038"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_sync_state",
        sa.Column("job_key", sa.String(40), primary_key=True),
        sa.Column("last_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "last_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "last_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "investigation_path_compute_state",
        sa.Column("organization_id", sa.String(26), primary_key=True),
        sa.Column("investigation_id", sa.String(26), primary_key=True),
        sa.Column("last_compute_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "pending_evidence_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_inv_path_compute_org_last",
        "investigation_path_compute_state",
        ["organization_id", "last_compute_at"],
    )

    op.add_column(
        "attack_paths",
        sa.Column("investigation_id", sa.String(26), nullable=True),
    )
    op.create_index(
        "ix_attack_paths_org_investigation",
        "attack_paths",
        ["organization_id", "investigation_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_attack_paths_org_investigation", table_name="attack_paths")
    op.drop_column("attack_paths", "investigation_id")
    op.drop_index(
        "ix_inv_path_compute_org_last",
        table_name="investigation_path_compute_state",
    )
    op.drop_table("investigation_path_compute_state")
    op.drop_table("threat_intel_sync_state")

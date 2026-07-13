"""Authorized Network Discovery & Adaptive Validation — M12.

Adds adaptive-plan provenance columns to `validation_execution_steps`
only — the smallest schema change that genuinely required a migration.
Everything else new in M12 (discovery port-policy version, discovery
bounds) is schemaless: it lives in the already-JSON `limits` column via
new `ExecutionLimits` dataclass fields (defaulted for backward
compatibility with every M11-era persisted execution).

Adds:
  - validation_execution_steps.source: "initial" (every M11 step, and
    NETWORK_DISCOVERY_BASELINE_V1's own initial plan) or "adaptive"
    (appended mid-execution by the deterministic adaptive rule
    registry — never client-submitted, never LLM-planned).
  - validation_execution_steps.adaptive_rule_id /
    adaptive_rule_version / source_fact_ref: provenance for an adaptive
    step only (NULL for every initial step) — which versioned rule
    fired, and which observed fact (e.g. "tcp_port:443:reachable")
    triggered it. An operator can audit exactly why an adaptive step
    exists from these three columns alone.

No new tables. No M13 schema. No credentials/tokens/cookies/private
material — same discipline as migration 0019.

Revision ID: 0020
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str = "0019"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.add_column(
        "validation_execution_steps",
        sa.Column("source", sa.String(20), nullable=False, server_default="initial"),
    )
    op.add_column(
        "validation_execution_steps",
        sa.Column("adaptive_rule_id", sa.String(60), nullable=True),
    )
    op.add_column(
        "validation_execution_steps",
        sa.Column("adaptive_rule_version", sa.Integer, nullable=True),
    )
    op.add_column(
        "validation_execution_steps",
        sa.Column("source_fact_ref", sa.String(120), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("validation_execution_steps", "source_fact_ref")
    op.drop_column("validation_execution_steps", "adaptive_rule_version")
    op.drop_column("validation_execution_steps", "adaptive_rule_id")
    op.drop_column("validation_execution_steps", "source")

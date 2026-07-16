"""Feed Synchronization Foundation — M22 Phase 2.

Two tables:

  1. feeds — the durable configuration + lifecycle state for one
     schedulable threat-intel source. Reuses the exact GLOBAL/TENANT
     `scope` + CHECK-constraint pattern migration 0035 introduced for
     `stix_ingestion_log`: a feed catalog entry is GLOBAL (no
     organization_id) when it applies to the whole platform (e.g. a
     future MITRE ATT&CK STIX feed, CISA KEV feed), or TENANT-scoped
     (organization_id required) for a future per-tenant subscription.
     Two separate partial unique indexes on `feed_key`, one per scope
     — never one shared index conflating both idempotency contracts,
     per the Hardening Review's Part 3 "Table Design Issues" finding.

  2. feed_sync_runs — execution-history rows for `feeds`, one per
     synchronization attempt. A partial unique index on `feed_id`
     WHERE status IN ('pending', 'running') enforces "at most one
     non-terminal run per feed" at the database layer — the
     authoritative, race-safe backstop behind the application-level
     PostgreSQL advisory lock the orchestration service also takes,
     so even a lock-acquisition bug can never produce two concurrent
     runs for the same feed.

No connector logic, no STIX/TAXII specifics, and no seeded rows — this
migration only creates the generic synchronization-platform schema
that a Phase 3 connector will register feeds against.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036"
down_revision: str = "0035"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_FEED_SCOPE_CHECK = (
    "(scope = 'GLOBAL' AND organization_id IS NULL) "
    "OR (scope = 'TENANT' AND organization_id IS NOT NULL)"
)


def upgrade() -> None:
    # ── feeds ────────────────────────────────────────────────────────────
    op.create_table(
        "feeds",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("feed_key", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("source_kind", sa.String(30), nullable=False),
        sa.Column("scope", sa.String(10), nullable=False, server_default="GLOBAL"),
        sa.Column("organization_id", sa.String(26), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("connector_config", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("credential_ref", sa.String(200), nullable=True),
        sa.Column("schedule_interval_seconds", sa.Integer, nullable=False),
        sa.Column("retry_max_attempts", sa.Integer, nullable=False, server_default="3"),
        sa.Column(
            "retry_base_delay_seconds", sa.Float, nullable=False, server_default="1.0"
        ),
        sa.Column(
            "retry_max_delay_seconds", sa.Float, nullable=False, server_default="30.0"
        ),
        sa.Column("retry_jitter_factor", sa.Float, nullable=False, server_default="0.25"),
        sa.Column("checkpoint", sa.Text, nullable=True),
        sa.Column(
            "consecutive_failure_count", sa.Integer, nullable=False, server_default="0"
        ),
        sa.Column("last_sync_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_status", sa.String(20), nullable=True),
        sa.Column("next_sync_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.Column("updated_by", sa.String(26), nullable=False),
        sa.CheckConstraint(_FEED_SCOPE_CHECK, name="ck_feeds_scope_org_pairing"),
    )
    op.create_index(
        "ux_feeds_global_key",
        "feeds",
        ["feed_key"],
        unique=True,
        postgresql_where=sa.text("scope = 'GLOBAL'"),
    )
    op.create_index(
        "ux_feeds_tenant_org_key",
        "feeds",
        ["organization_id", "feed_key"],
        unique=True,
        postgresql_where=sa.text("scope = 'TENANT'"),
    )
    op.create_index("ix_feeds_status", "feeds", ["status"])
    op.create_index("ix_feeds_source_kind", "feeds", ["source_kind"])
    op.create_index("ix_feeds_organization_id", "feeds", ["organization_id"])
    # Scheduler-worker query path: `list_due_for_sync` scans ACTIVE feeds
    # ordered by due time — a partial index scoped to the one status the
    # worker ever polls keeps that scan tight even as DRAFT/DISABLED
    # feeds accumulate.
    op.create_index(
        "ix_feeds_active_next_sync_due",
        "feeds",
        ["next_sync_due_at"],
        postgresql_where=sa.text("status = 'active'"),
    )

    # ── feed_sync_runs ───────────────────────────────────────────────────
    op.create_table(
        "feed_sync_runs",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("feed_id", sa.String(26), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("trigger", sa.String(20), nullable=False),
        sa.Column("checkpoint_before", sa.Text, nullable=True),
        sa.Column("checkpoint_after", sa.Text, nullable=True),
        sa.Column("items_fetched", sa.Integer, nullable=False, server_default="0"),
        sa.Column("items_processed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("items_failed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("retry_attempts_used", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(26), nullable=False),
        sa.ForeignKeyConstraint(
            ["feed_id"],
            ["feeds.id"],
            name="fk_fsr_feed",
            ondelete="CASCADE",
        ),
    )
    # The database-level idempotency/concurrency backstop: at most one
    # non-terminal run per feed, independent of the advisory lock the
    # orchestration service also takes.
    op.create_index(
        "ux_fsr_feed_active_run",
        "feed_sync_runs",
        ["feed_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )
    op.create_index("ix_fsr_feed_started", "feed_sync_runs", ["feed_id", "started_at"])
    op.create_index("ix_fsr_status", "feed_sync_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_fsr_status", table_name="feed_sync_runs")
    op.drop_index("ix_fsr_feed_started", table_name="feed_sync_runs")
    op.drop_index("ux_fsr_feed_active_run", table_name="feed_sync_runs")
    op.drop_constraint("fk_fsr_feed", "feed_sync_runs", type_="foreignkey")
    op.drop_table("feed_sync_runs")

    op.drop_index("ix_feeds_active_next_sync_due", table_name="feeds")
    op.drop_index("ix_feeds_organization_id", table_name="feeds")
    op.drop_index("ix_feeds_source_kind", table_name="feeds")
    op.drop_index("ix_feeds_status", table_name="feeds")
    op.drop_index("ux_feeds_tenant_org_key", table_name="feeds")
    op.drop_index("ux_feeds_global_key", table_name="feeds")
    op.drop_constraint("ck_feeds_scope_org_pairing", "feeds", type_="check")
    op.drop_table("feeds")

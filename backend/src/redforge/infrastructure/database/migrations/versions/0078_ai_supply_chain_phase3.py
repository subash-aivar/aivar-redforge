
"""0078 — M31 Phase 3 ai_supply_chain.

Creates ai_supply_chain schema with model provenance, append-only chain entries,
MBOM tables, discovery scan runs, and tenant verification settings.

Database-level immutability: UPDATE/DELETE triggers on provenance_chain_entries
and mbom_components (legally_significant_audit_trail: true).

Migration chain: 0077 → 0078.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0078"
down_revision: str = "0077"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS ai_supply_chain")

    op.create_table(
        "model_provenance",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("ai_system_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_origin", sa.String(64), nullable=False),
        sa.Column("integrity_status", sa.String(64), nullable=False, index=True),
        sa.Column("operational_status", sa.String(64), nullable=False),
        sa.Column("artifact_size_bytes", sa.Integer(), nullable=False),
        sa.Column("current_checksum_json", postgresql.JSONB(), nullable=True),
        sa.Column("last_verified_checksum_json", postgresql.JSONB(), nullable=True),
        sa.Column("signature_chain_json", postgresql.JSONB(), nullable=True),
        sa.Column("source_registry_json", postgresql.JSONB(), nullable=True),
        sa.Column("training_lineage_json", postgresql.JSONB(), nullable=True),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id", "ai_system_asset_id", name="uq_model_provenance_tenant_asset"
        ),
        schema="ai_supply_chain",
        comment="legally_significant_audit_trail: related",
    )

    op.create_table(
        "provenance_chain_entries",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("provenance_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("entry_kind", sa.String(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verification_method", sa.String(64), nullable=True),
        sa.Column("trust_delegation_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        schema="ai_supply_chain",
        comment="legally_significant_audit_trail: true",
    )

    op.create_table(
        "model_bill_of_materials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provenance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("completed", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id", "provenance_id", name="uq_mbom_tenant_provenance"
        ),
        schema="ai_supply_chain",
    )

    op.create_table(
        "mbom_components",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mbom_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("component_type", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("version", sa.String(128), nullable=False),
        sa.Column("source", sa.String(256), nullable=False),
        sa.Column("checksum", sa.String(128), nullable=False),
        sa.Column(
            "known_cve_ids_json",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
        ),
        schema="ai_supply_chain",
        comment="legally_significant_audit_trail: true",
    )

    op.create_table(
        "ai_discovery_scan_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("state", sa.String(64), nullable=False),
        sa.Column("sources_json", postgresql.JSONB(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovered_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unmatched_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "failed_partitions_json",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("api_calls_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("partial", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "payload_json", postgresql.JSONB(), nullable=False, server_default="{}"
        ),
        schema="ai_supply_chain",
    )

    op.create_table(
        "tenant_verification_settings",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("size_threshold_bytes", sa.BigInteger(), nullable=False),
        sa.Column("monthly_egress_budget_bytes", sa.BigInteger(), nullable=False),
        sa.Column("egress_bytes_used", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("max_api_calls_per_scan", sa.Integer(), nullable=False, server_default="1000"),
        sa.Column("max_concurrent_accounts", sa.Integer(), nullable=False, server_default="5"),
        schema="ai_supply_chain",
    )

    # Append-only enforcement (preferred trigger approach alongside RLS ops guidance)
    op.execute(
        """
        CREATE OR REPLACE FUNCTION ai_supply_chain.reject_mutation()
        RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'append-only table: UPDATE/DELETE not permitted on %', TG_TABLE_NAME;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER provenance_chain_entries_immutable
        BEFORE UPDATE OR DELETE ON ai_supply_chain.provenance_chain_entries
        FOR EACH ROW EXECUTE PROCEDURE ai_supply_chain.reject_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER mbom_components_immutable
        BEFORE UPDATE OR DELETE ON ai_supply_chain.mbom_components
        FOR EACH ROW EXECUTE PROCEDURE ai_supply_chain.reject_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS mbom_components_immutable ON ai_supply_chain.mbom_components")
    op.execute(
        "DROP TRIGGER IF EXISTS provenance_chain_entries_immutable "
        "ON ai_supply_chain.provenance_chain_entries"
    )
    op.execute("DROP FUNCTION IF EXISTS ai_supply_chain.reject_mutation()")
    op.drop_table("tenant_verification_settings", schema="ai_supply_chain")
    op.drop_table("ai_discovery_scan_runs", schema="ai_supply_chain")
    op.drop_table("mbom_components", schema="ai_supply_chain")
    op.drop_table("model_bill_of_materials", schema="ai_supply_chain")
    op.drop_table("provenance_chain_entries", schema="ai_supply_chain")
    op.drop_table("model_provenance", schema="ai_supply_chain")
    op.execute("DROP SCHEMA IF EXISTS ai_supply_chain CASCADE")

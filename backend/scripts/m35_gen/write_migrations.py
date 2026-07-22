"""Generate M35 Alembic migrations 0114–0130."""

from __future__ import annotations

from .common import MIG, TESTS, w


def write() -> None:
    _write_all()


def _mig(rev: str, down: str, name: str, upgrade: str, downgrade: str) -> None:
    w(
        MIG / f"{rev}_{name}.py",
        f'''"""{rev} — M35 migration.

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


def _write_all() -> None:
    _mig(
        "0114",
        "0113",
        "playbooks_core",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS playbook")
    op.create_table(
        "playbooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("current_version_number", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_impact_level", sa.String(20), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="playbook",
    )
    op.create_index("ix_playbooks_tenant_status", "playbooks", ["tenant_id", "status"], schema="playbook")
    op.create_index("ix_playbooks_tenant_name", "playbooks", ["tenant_id", "name"], schema="playbook")
''',
        '''
    op.drop_index("ix_playbooks_tenant_name", table_name="playbooks", schema="playbook")
    op.drop_index("ix_playbooks_tenant_status", table_name="playbooks", schema="playbook")
    op.drop_table("playbooks", schema="playbook")
    op.execute("DROP SCHEMA IF EXISTS playbook CASCADE")
''',
    )
    _mig(
        "0115",
        "0114",
        "playbook_versions",
        '''
    op.create_table(
        "playbook_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("playbook.playbooks.id"), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False, server_default=""),
        sa.Column("published_by", sa.Text(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("playbook_id", "version_number", name="uq_playbook_version"),
        schema="playbook",
    )
    op.create_index("ix_playbook_versions_tenant_status", "playbook_versions", ["tenant_id", "status"], schema="playbook")
''',
        '''
    op.drop_index("ix_playbook_versions_tenant_status", table_name="playbook_versions", schema="playbook")
    op.drop_table("playbook_versions", schema="playbook")
''',
    )
    _mig(
        "0116",
        "0115",
        "playbook_action_steps",
        '''
    op.create_table(
        "playbook_action_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("playbook.playbook_versions.id"), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("target_selector_expr", sa.Text(), nullable=False),
        sa.Column("parameters", postgresql.JSONB(), nullable=False),
        sa.Column("impact_level", sa.String(20), nullable=False),
        sa.Column("rollback_definition", postgresql.JSONB(), nullable=True),
        sa.Column("max_execution_seconds", sa.Integer(), nullable=False, server_default="120"),
        schema="playbook",
    )
    op.create_index("ix_playbook_action_steps_version_step", "playbook_action_steps", ["version_id", "step_number"], schema="playbook")
''',
        '''
    op.drop_index("ix_playbook_action_steps_version_step", table_name="playbook_action_steps", schema="playbook")
    op.drop_table("playbook_action_steps", schema="playbook")
''',
    )
    _mig(
        "0117",
        "0116",
        "playbook_trigger_configs",
        '''
    op.create_table(
        "playbook_trigger_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("playbook.playbooks.id"), nullable=False),
        sa.Column("source_context", sa.String(40), nullable=False),
        sa.Column("trigger_type", sa.Text(), nullable=False),
        sa.Column("severity_threshold", sa.String(40), nullable=True),
        sa.Column("asset_tag_filter", postgresql.JSONB(), nullable=True),
        sa.Column("rate_limit_window_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("rate_limit_max_invocations", sa.Integer(), nullable=False, server_default="1"),
        schema="playbook",
    )
    op.create_index(
        "ix_playbook_triggers_tenant_source_type",
        "playbook_trigger_configs",
        ["tenant_id", "source_context", "trigger_type"],
        schema="playbook",
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_playbook_triggers_asset_tags "
        "ON playbook.playbook_trigger_configs USING GIN (asset_tag_filter)"
    )
''',
        '''
    op.execute("DROP INDEX IF EXISTS playbook.ix_playbook_triggers_asset_tags")
    op.drop_index("ix_playbook_triggers_tenant_source_type", table_name="playbook_trigger_configs", schema="playbook")
    op.drop_table("playbook_trigger_configs", schema="playbook")
''',
    )
    _mig(
        "0118",
        "0117",
        "playbook_test_results",
        '''
    op.create_table(
        "playbook_test_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("playbook.playbook_versions.id"), nullable=False),
        sa.Column("content_hash_at_test", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("steps_tested", sa.Integer(), nullable=False),
        sa.Column("steps_passed", sa.Integer(), nullable=False),
        sa.Column("coverage_paths", postgresql.JSONB(), nullable=False),
        sa.Column("executed_by", sa.Text(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        schema="playbook",
    )
    op.create_index(
        "ix_playbook_test_results_pb_ver_at",
        "playbook_test_results",
        ["playbook_id", "version_id", "executed_at"],
        schema="playbook",
    )
''',
        '''
    op.drop_index("ix_playbook_test_results_pb_ver_at", table_name="playbook_test_results", schema="playbook")
    op.drop_table("playbook_test_results", schema="playbook")
''',
    )
    _mig(
        "0119",
        "0118",
        "automation_policy",
        '''
    op.create_table(
        "automation_policy",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kill_switch_state", sa.String(20), nullable=False, server_default="ARMED"),
        sa.Column("kill_switch_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kill_switch_triggered_by", sa.Text(), nullable=True),
        sa.Column("max_concurrent_executions", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("max_actions_per_hour", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("allowed_connector_types", postgresql.JSONB(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="playbook",
    )
''',
        '''
    op.drop_table("automation_policy", schema="playbook")
''',
    )
    _mig(
        "0120",
        "0119",
        "automation_executions",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS automated_action")
    op.create_table(
        "automation_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("playbook_version", sa.Integer(), nullable=False),
        sa.Column("playbook_content_hash", sa.String(64), nullable=False),
        sa.Column("trigger_source_context", sa.String(40), nullable=False),
        sa.Column("source_event_id", sa.Text(), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("operator_id", sa.Text(), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("total_steps", sa.Integer(), nullable=False),
        sa.Column("max_impact_level", sa.String(20), nullable=False),
        sa.Column("escalation_request", postgresql.JSONB(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        schema="automated_action",
    )
    op.create_index("ix_auto_exec_tenant_pb", "automation_executions", ["tenant_id", "playbook_id"], schema="automated_action")
    op.create_index("ix_auto_exec_tenant_status", "automation_executions", ["tenant_id", "status"], schema="automated_action")
    op.create_index("ix_auto_exec_tenant_created", "automation_executions", ["tenant_id", "created_at"], schema="automated_action")
    op.create_index("ix_auto_exec_source_event", "automation_executions", ["source_event_id"], schema="automated_action")
''',
        '''
    op.drop_index("ix_auto_exec_source_event", table_name="automation_executions", schema="automated_action")
    op.drop_index("ix_auto_exec_tenant_created", table_name="automation_executions", schema="automated_action")
    op.drop_index("ix_auto_exec_tenant_status", table_name="automation_executions", schema="automated_action")
    op.drop_index("ix_auto_exec_tenant_pb", table_name="automation_executions", schema="automated_action")
    op.drop_table("automation_executions", schema="automated_action")
    op.execute("DROP SCHEMA IF EXISTS automated_action CASCADE")
''',
    )
    _mig(
        "0121",
        "0120",
        "automated_action_records",
        '''
    op.create_table(
        "automated_action_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("target_resource", sa.Text(), nullable=False),
        sa.Column("parameters_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=True),
        sa.Column("external_reference", sa.Text(), nullable=True),
        sa.Column("failure_mode", sa.String(40), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("rollback_available", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("rollback_parameters_ref", sa.Text(), nullable=True),
        schema="automated_action",
    )
    op.create_index("ix_aar_execution", "automated_action_records", ["execution_id"], schema="automated_action")
    op.create_index("ix_aar_tenant_connector", "automated_action_records", ["tenant_id", "connector_type"], schema="automated_action")
    op.create_index("ix_aar_tenant_attempted", "automated_action_records", ["tenant_id", "attempted_at"], schema="automated_action")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_aar_pending_attempted "
        "ON automated_action.automated_action_records (status, attempted_at) "
        "WHERE status = 'PENDING'"
    )
''',
        '''
    op.execute("DROP INDEX IF EXISTS automated_action.ix_aar_pending_attempted")
    op.drop_index("ix_aar_tenant_attempted", table_name="automated_action_records", schema="automated_action")
    op.drop_index("ix_aar_tenant_connector", table_name="automated_action_records", schema="automated_action")
    op.drop_index("ix_aar_execution", table_name="automated_action_records", schema="automated_action")
    op.drop_table("automated_action_records", schema="automated_action")
''',
    )
    _mig(
        "0122",
        "0121",
        "rollback_records",
        '''
    op.create_table(
        "rollback_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("original_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rollback_status", sa.String(30), nullable=False),
        sa.Column("initiated_by", sa.Text(), nullable=False),
        sa.Column("initiated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        schema="automated_action",
    )
    op.create_index("ix_rollback_execution", "rollback_records", ["execution_id"], schema="automated_action")
    op.create_index("ix_rollback_original", "rollback_records", ["original_record_id"], schema="automated_action")
    op.create_index("ix_rollback_tenant_status", "rollback_records", ["tenant_id", "rollback_status"], schema="automated_action")
''',
        '''
    op.drop_index("ix_rollback_tenant_status", table_name="rollback_records", schema="automated_action")
    op.drop_index("ix_rollback_original", table_name="rollback_records", schema="automated_action")
    op.drop_index("ix_rollback_execution", table_name="rollback_records", schema="automated_action")
    op.drop_table("rollback_records", schema="automated_action")
''',
    )
    _mig(
        "0123",
        "0122",
        "automation_kill_switch_log",
        '''
    op.create_table(
        "automation_kill_switch_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        schema="automated_action",
    )
    op.create_index("ix_kill_switch_log_tenant_at", "automation_kill_switch_log", ["tenant_id", "recorded_at"], schema="automated_action")
''',
        '''
    op.drop_index("ix_kill_switch_log_tenant_at", table_name="automation_kill_switch_log", schema="automated_action")
    op.drop_table("automation_kill_switch_log", schema="automated_action")
''',
    )
    _mig(
        "0124",
        "0123",
        "escalation_records",
        '''
    op.create_table(
        "escalation_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("step_number", sa.Integer(), nullable=False),
        sa.Column("impact_level", sa.String(20), nullable=False),
        sa.Column("required_role", sa.String(50), nullable=False),
        sa.Column("trigger_operator_id", sa.Text(), nullable=False),
        sa.Column("escalated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_by", sa.Text(), nullable=True),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution", sa.String(20), nullable=True),
        schema="automated_action",
    )
    op.create_index("ix_escalation_execution", "escalation_records", ["execution_id"], schema="automated_action")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_escalation_pending "
        "ON automated_action.escalation_records (tenant_id, resolution) "
        "WHERE resolution IS NULL"
    )
''',
        '''
    op.execute("DROP INDEX IF EXISTS automated_action.ix_escalation_pending")
    op.drop_index("ix_escalation_execution", table_name="escalation_records", schema="automated_action")
    op.drop_table("escalation_records", schema="automated_action")
''',
    )
    _mig(
        "0125",
        "0124",
        "integration_hub_connectors",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS integration_hub")
    op.create_table(
        "connector_registrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_type", sa.String(50), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="REGISTERED"),
        sa.Column("credential_vault_key", sa.Text(), nullable=False),
        sa.Column("credential_type", sa.String(30), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=True),
        sa.Column("configuration", postgresql.JSONB(), nullable=True),
        sa.Column("circuit_state", sa.String(20), nullable=False, server_default="CLOSED"),
        sa.Column("circuit_failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("circuit_opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        schema="integration_hub",
    )
    op.create_index("ix_connectors_tenant_type", "connector_registrations", ["tenant_id", "connector_type"], schema="integration_hub")
    op.create_index("ix_connectors_tenant_status", "connector_registrations", ["tenant_id", "status"], schema="integration_hub")
''',
        '''
    op.drop_index("ix_connectors_tenant_status", table_name="connector_registrations", schema="integration_hub")
    op.drop_index("ix_connectors_tenant_type", table_name="connector_registrations", schema="integration_hub")
    op.drop_table("connector_registrations", schema="integration_hub")
    op.execute("DROP SCHEMA IF EXISTS integration_hub CASCADE")
''',
    )
    _mig(
        "0126",
        "0125",
        "connector_health_records",
        '''
    op.create_table(
        "connector_health_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("response_time_ms", sa.Integer(), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        schema="integration_hub",
    )
    op.create_index("ix_connector_health_conn_at", "connector_health_records", ["connector_id", "checked_at"], schema="integration_hub")
''',
        '''
    op.drop_index("ix_connector_health_conn_at", table_name="connector_health_records", schema="integration_hub")
    op.drop_table("connector_health_records", schema="integration_hub")
''',
    )
    _mig(
        "0127",
        "0126",
        "connector_action_audit",
        '''
    op.create_table(
        "connector_action_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        schema="integration_hub",
    )
    op.create_index("ix_caa_connector_at", "connector_action_audit", ["connector_id", "executed_at"], schema="integration_hub")
    op.create_index("ix_caa_tenant_at", "connector_action_audit", ["tenant_id", "executed_at"], schema="integration_hub")
''',
        '''
    op.drop_index("ix_caa_tenant_at", table_name="connector_action_audit", schema="integration_hub")
    op.drop_index("ix_caa_connector_at", table_name="connector_action_audit", schema="integration_hub")
    op.drop_table("connector_action_audit", schema="integration_hub")
''',
    )
    _mig(
        "0128",
        "0127",
        "rate_limit_tracking",
        '''
    op.create_table(
        "connector_rate_limit_tracking",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action_count", sa.Integer(), nullable=False),
        sa.Column("budget_consumed_percent", sa.Float(), nullable=False),
        schema="integration_hub",
    )
    op.create_index("ix_rate_limit_conn_start", "connector_rate_limit_tracking", ["connector_id", "window_start"], schema="integration_hub")
''',
        '''
    op.drop_index("ix_rate_limit_conn_start", table_name="connector_rate_limit_tracking", schema="integration_hub")
    op.drop_table("connector_rate_limit_tracking", schema="integration_hub")
''',
    )
    _mig(
        "0129",
        "0128",
        "security_graph_m35_nodes",
        '''
    # Extend graph enums via lookup tables when present; otherwise no-op safe inserts.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'node_types'
            ) THEN
                INSERT INTO security_graph.node_types(node_type)
                VALUES ('playbook'), ('automated_action')
                ON CONFLICT DO NOTHING;
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                INSERT INTO security_graph.edge_types(edge_type)
                VALUES ('triggered_playbook'), ('executed_action'), ('action_on_asset'), ('rolled_back_by')
                ON CONFLICT DO NOTHING;
            END IF;
        END $$;
        """
    )
''',
        '''
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'node_types'
            ) THEN
                DELETE FROM security_graph.node_types
                WHERE node_type IN ('playbook', 'automated_action');
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                DELETE FROM security_graph.edge_types
                WHERE edge_type IN ('triggered_playbook', 'executed_action', 'action_on_asset', 'rolled_back_by');
            END IF;
        END $$;
        """
    )
''',
    )
    _mig(
        "0130",
        "0129",
        "m35_analytics_projection",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
    op.create_table(
        "automation_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("playbook_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("outcome", sa.String(40), nullable=True),
        sa.Column("action_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index("ix_automation_events_tenant_ts", "automation_events", ["tenant_id", "event_ts"], schema="analytics")
    op.create_index("ix_automation_events_tenant_pb_ts", "automation_events", ["tenant_id", "playbook_id", "event_ts"], schema="analytics")
''',
        '''
    op.drop_index("ix_automation_events_tenant_pb_ts", table_name="automation_events", schema="analytics")
    op.drop_index("ix_automation_events_tenant_ts", table_name="automation_events", schema="analytics")
    op.drop_table("automation_events", schema="analytics")
''',
    )
    w(
        TESTS / "playbook" / "test_migration_chain.py",
        '''from __future__ import annotations

import re
from pathlib import Path

MIG = Path(__file__).resolve().parents[2] / "src" / "redforge" / "infrastructure" / "database" / "migrations" / "versions"


def test_m35_migration_chain_linear() -> None:
    expected = [f"{i:04d}" for i in range(114, 131)]
    files = sorted(MIG.glob("01*.py"))
    revs = {}
    for f in files:
        text = f.read_text()
        rev_m = re.search(r'revision:\\s*str\\s*=\\s*"(\\d+)"', text)
        down_m = re.search(r'down_revision:\\s*str\\s*=\\s*"(\\d+)"', text)
        if rev_m:
            revs[rev_m.group(1)] = down_m.group(1) if down_m else None
    for rev in expected:
        assert rev in revs, f"missing migration {rev}"
    assert revs["0114"] == "0113"
    for i in range(115, 131):
        assert revs[f"{i:04d}"] == f"{i-1:04d}"
    # single head
    heads = [r for r in revs if r not in set(revs.values())]
    m35_heads = [h for h in heads if h >= "0114"]
    assert "0130" in m35_heads
''',
    )

"""Security Operations Command Center — M15.

Reconnaissance finding that shaped this migration: the pre-existing
Sprint 24/25 generic `platform_events` event-sourcing table (migration
0007) is fully built (global_position sequence, tenant-scoped, ordered
indexes) but has ZERO production writers — every bounded context that
calls `collect_events()` (organizations, memberships, targets, ...)
publishes through `EventPublisherPort`, whose only real implementation
is `infrastructure/events.py`'s `NullEventPublisher` — a no-op. Rather
than resurrect that entirely-untested-in-production subsystem for the
first time under this milestone, inside the same edit that also has to
touch the 1000+-line, 3900-test-covered `execution_service.py` dispatch
loop, M15 instead extends the two bounded contexts that ALREADY have
genuine, comprehensive, production-proven durable event logs
(`validation_execution_events` from M11, `security_drift_events` from
M14) and adds small, additive, purpose-built tables for the two real
gaps reconnaissance found:

  - continuous_validation_policy_lifecycle_events: M14's
    ContinuousValidationPolicy had NO durable transition log at all —
    only the current `lifecycle` column survived. Append-only, mirrors
    security_drift_events' shape exactly.
  - runtime_component_health_state / runtime_component_health_transitions:
    runtime health (application/platform/dynamic_health.py) was, and
    remains, 100% live-computed on every call with zero persistence or
    transition memory. `..._state` remembers the last-emitted status
    per platform-wide component purely to dedupe repeated same-state
    observations across polls/restarts/instances;
    `..._transitions` is the durable, append-only HEALTHY<->UNHEALTHY
    history that actually feeds the operational event feed. Neither
    table is tenant-scoped — runtime components are platform-wide.

The unified cross-domain "Security Operations" event feed is a
query-time merge across validation_execution_events,
security_drift_events, continuous_validation_policy_lifecycle_events,
and runtime_component_health_transitions — not a single physical event
table. See docs/M15_SECURITY_OPERATIONS_COMMAND_CENTER_REPORT.md §1-2
for the full architecture decision and the trade-off this represents
against the textbook "one global event store" answer.

Security operations summary/change-feed/execution-list endpoints
themselves need NO new persistence — they are live aggregation queries
over already-existing tables.

Revision ID: 0023
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str = "0022"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "continuous_validation_policy_lifecycle_events",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("policy_id", sa.String(26), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["continuous_validation_policies.id", "continuous_validation_policies.organization_id"],
            name="fk_cvple_same_tenant_policy",
        ),
        sa.UniqueConstraint("id", "organization_id", name="ux_cvple_id_org"),
    )
    op.create_index(
        "ix_cvple_org_occurred", "continuous_validation_policy_lifecycle_events",
        ["organization_id", "occurred_at"],
    )

    op.create_table(
        "runtime_component_health_state",
        sa.Column("component_id", sa.String(100), primary_key=True, nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "runtime_component_health_transitions",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("component_id", sa.String(100), nullable=False),
        sa.Column("old_status", sa.String(20), nullable=False),
        sa.Column("new_status", sa.String(20), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_rcht_component_occurred", "runtime_component_health_transitions",
        ["component_id", "occurred_at"],
    )
    op.create_index(
        "ix_rcht_occurred", "runtime_component_health_transitions", ["occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_rcht_occurred", table_name="runtime_component_health_transitions")
    op.drop_index("ix_rcht_component_occurred", table_name="runtime_component_health_transitions")
    op.drop_table("runtime_component_health_transitions")

    op.drop_table("runtime_component_health_state")

    op.drop_index(
        "ix_cvple_org_occurred", table_name="continuous_validation_policy_lifecycle_events",
    )
    op.drop_table("continuous_validation_policy_lifecycle_events")

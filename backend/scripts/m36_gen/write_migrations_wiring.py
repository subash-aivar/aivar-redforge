"""M36 migrations 0131–0149, API wiring, outbound ACL subscribers."""

from __future__ import annotations

from .common import MIG, ROOT, SRC, TESTS, mig, w


def write() -> None:
    _migrations()
    _outbound_acl()
    _wiring()
    _update_migration_tests()


def _migrations() -> None:
    mig(
        "0131",
        "0130",
        "autonomous_intelligence_schema",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS autonomous_intelligence")
''',
        '''
    op.execute("DROP SCHEMA IF EXISTS autonomous_intelligence CASCADE")
''',
    )
    mig(
        "0132",
        "0131",
        "optimization_models",
        '''
    op.create_table(
        "optimization_models",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("accuracy_metrics", postgresql.JSONB(), nullable=False),
        sa.Column("conformity_assessment_ref", sa.Text(), nullable=True),
        sa.Column("feedback_sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("retraining_threshold", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        schema="autonomous_intelligence",
    )
    op.create_index("ix_opt_models_tenant_type_status", "optimization_models", ["tenant_id", "target_type", "status"], schema="autonomous_intelligence")
''',
        '''
    op.drop_index("ix_opt_models_tenant_type_status", table_name="optimization_models", schema="autonomous_intelligence")
    op.drop_table("optimization_models", schema="autonomous_intelligence")
''',
    )
    mig(
        "0133",
        "0132",
        "intelligence_suggestions",
        '''
    op.create_table(
        "intelligence_suggestions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("target_context", sa.String(80), nullable=False),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("rationale_summary", sa.Text(), nullable=False),
        sa.Column("supporting_signal_refs", postgresql.JSONB(), nullable=False),
        sa.Column("proposed_change_payload", postgresql.JSONB(), nullable=False),
        sa.Column("priority", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("review_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.Text(), nullable=True),
        sa.Column("rejected_by", sa.Text(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        schema="autonomous_intelligence",
    )
    op.create_index("ix_suggestions_tenant_status", "intelligence_suggestions", ["tenant_id", "status"], schema="autonomous_intelligence")
    op.create_index("ix_suggestions_tenant_type_conf", "intelligence_suggestions", ["tenant_id", "target_type", "confidence_score"], schema="autonomous_intelligence")
    op.create_index("ix_suggestions_deadline", "intelligence_suggestions", ["status", "review_deadline_at"], schema="autonomous_intelligence")
''',
        '''
    op.drop_index("ix_suggestions_deadline", table_name="intelligence_suggestions", schema="autonomous_intelligence")
    op.drop_index("ix_suggestions_tenant_type_conf", table_name="intelligence_suggestions", schema="autonomous_intelligence")
    op.drop_index("ix_suggestions_tenant_status", table_name="intelligence_suggestions", schema="autonomous_intelligence")
    op.drop_table("intelligence_suggestions", schema="autonomous_intelligence")
''',
    )
    mig(
        "0134",
        "0133",
        "suggestion_outcomes",
        '''
    op.create_table(
        "suggestion_outcomes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("suggestion_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("outcome_type", sa.String(40), nullable=False),
        sa.Column("measurement_window_days", sa.Integer(), nullable=False),
        sa.Column("baseline_metric", sa.Float(), nullable=False),
        sa.Column("observed_metric", sa.Float(), nullable=True),
        sa.Column("delta", sa.Float(), nullable=True),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=True),
        schema="autonomous_intelligence",
    )
    op.create_index("ix_outcomes_suggestion", "suggestion_outcomes", ["suggestion_id"], schema="autonomous_intelligence")
    op.create_index("ix_outcomes_tenant_type", "suggestion_outcomes", ["tenant_id", "target_type"], schema="autonomous_intelligence")
''',
        '''
    op.drop_index("ix_outcomes_tenant_type", table_name="suggestion_outcomes", schema="autonomous_intelligence")
    op.drop_index("ix_outcomes_suggestion", table_name="suggestion_outcomes", schema="autonomous_intelligence")
    op.drop_table("suggestion_outcomes", schema="autonomous_intelligence")
''',
    )
    mig(
        "0135",
        "0134",
        "autonomous_operations_policies",
        '''
    op.create_table(
        "autonomous_operations_policies",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kill_switch_active", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("review_required", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("min_confidence_by_type", postgresql.JSONB(), nullable=False),
        sa.Column("enabled_target_types", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema="autonomous_intelligence",
    )
''',
        '''
    op.drop_table("autonomous_operations_policies", schema="autonomous_intelligence")
''',
    )
    mig(
        "0136",
        "0135",
        "llm_inference_audit_log",
        '''
    op.create_table(
        "llm_inference_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("prompt_token_count", sa.Integer(), nullable=False),
        sa.Column("completion_token_count", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        schema="autonomous_intelligence",
    )
    op.create_index("ix_llm_audit_tenant_at", "llm_inference_audit_log", ["tenant_id", "recorded_at"], schema="autonomous_intelligence")
''',
        '''
    op.drop_index("ix_llm_audit_tenant_at", table_name="llm_inference_audit_log", schema="autonomous_intelligence")
    op.drop_table("llm_inference_audit_log", schema="autonomous_intelligence")
''',
    )
    mig(
        "0137",
        "0136",
        "model_training_jobs",
        '''
    op.create_table(
        "model_training_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        schema="autonomous_intelligence",
    )
    op.create_index("ix_training_jobs_tenant_status", "model_training_jobs", ["tenant_id", "status"], schema="autonomous_intelligence")
''',
        '''
    op.drop_index("ix_training_jobs_tenant_status", table_name="model_training_jobs", schema="autonomous_intelligence")
    op.drop_table("model_training_jobs", schema="autonomous_intelligence")
''',
    )
    mig(
        "0138",
        "0137",
        "posture_forecasting_schema",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS posture_forecasting")
''',
        '''
    op.execute("DROP SCHEMA IF EXISTS posture_forecasting CASCADE")
''',
    )
    mig(
        "0139",
        "0138",
        "posture_forecasts",
        '''
    op.create_table(
        "posture_forecasts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("predicted_30d", sa.Float(), nullable=False),
        sa.Column("predicted_60d", sa.Float(), nullable=False),
        sa.Column("predicted_90d", sa.Float(), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("model_version", sa.Integer(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        schema="posture_forecasting",
    )
    op.create_index("ix_forecasts_tenant_generated", "posture_forecasts", ["tenant_id", "generated_at"], schema="posture_forecasting")
''',
        '''
    op.drop_index("ix_forecasts_tenant_generated", table_name="posture_forecasts", schema="posture_forecasting")
    op.drop_table("posture_forecasts", schema="posture_forecasting")
''',
    )
    mig(
        "0140",
        "0139",
        "forecast_accuracy_records",
        '''
    op.create_table(
        "forecast_accuracy_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("forecast_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("horizon_days", sa.Integer(), nullable=False),
        sa.Column("actual_score", sa.Float(), nullable=False),
        sa.Column("predicted_score", sa.Float(), nullable=False),
        sa.Column("absolute_error", sa.Float(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        schema="posture_forecasting",
    )
    op.create_index("ix_forecast_acc_forecast", "forecast_accuracy_records", ["forecast_id", "horizon_days"], schema="posture_forecasting")
''',
        '''
    op.drop_index("ix_forecast_acc_forecast", table_name="forecast_accuracy_records", schema="posture_forecasting")
    op.drop_table("forecast_accuracy_records", schema="posture_forecasting")
''',
    )
    mig(
        "0141",
        "0140",
        "forecast_configurations",
        '''
    op.create_table(
        "forecast_configurations",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("forecast_frequency_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("signal_weights", postgresql.JSONB(), nullable=False),
        schema="posture_forecasting",
    )
''',
        '''
    op.drop_table("forecast_configurations", schema="posture_forecasting")
''',
    )
    mig(
        "0142",
        "0141",
        "posture_forecast_input_snapshots",
        '''
    op.create_table(
        "forecast_input_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("forecast_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("baseline_exposure_score", sa.Float(), nullable=False),
        sa.Column("remediation_velocity_per_day", sa.Float(), nullable=False),
        sa.Column("open_critical_count", sa.Integer(), nullable=False),
        sa.Column("open_high_count", sa.Integer(), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        schema="posture_forecasting",
    )
    op.create_index("ix_forecast_snap_forecast", "forecast_input_snapshots", ["forecast_id"], schema="posture_forecasting")
''',
        '''
    op.drop_index("ix_forecast_snap_forecast", table_name="forecast_input_snapshots", schema="posture_forecasting")
    op.drop_table("forecast_input_snapshots", schema="posture_forecasting")
''',
    )
    mig(
        "0143",
        "0142",
        "threat_hunt_schema",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS threat_hunt")
''',
        '''
    op.execute("DROP SCHEMA IF EXISTS threat_hunt CASCADE")
''',
    )
    mig(
        "0144",
        "0143",
        "threat_hunt_candidates",
        '''
    op.create_table(
        "threat_hunt_candidates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("detection_logic_draft", sa.Text(), nullable=False),
        sa.Column("detection_rule_format", sa.String(20), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("candidate_status", sa.String(30), nullable=False),
        sa.Column("promoted_rule_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        schema="threat_hunt",
    )
    op.create_index("ix_hunt_candidates_tenant_status", "threat_hunt_candidates", ["tenant_id", "candidate_status"], schema="threat_hunt")
''',
        '''
    op.drop_index("ix_hunt_candidates_tenant_status", table_name="threat_hunt_candidates", schema="threat_hunt")
    op.drop_table("threat_hunt_candidates", schema="threat_hunt")
''',
    )
    mig(
        "0145",
        "0144",
        "threat_hunt_anomaly_signal_refs",
        '''
    op.create_table(
        "threat_hunt_anomaly_signal_refs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("signal_id", sa.Text(), nullable=False),
        sa.Column("source", sa.String(80), nullable=False),
        schema="threat_hunt",
    )
    op.create_index("ix_hunt_signal_candidate", "threat_hunt_anomaly_signal_refs", ["candidate_id"], schema="threat_hunt")
''',
        '''
    op.drop_index("ix_hunt_signal_candidate", table_name="threat_hunt_anomaly_signal_refs", schema="threat_hunt")
    op.drop_table("threat_hunt_anomaly_signal_refs", schema="threat_hunt")
''',
    )
    mig(
        "0146",
        "0145",
        "threat_hunt_configurations",
        '''
    op.create_table(
        "threat_hunt_configurations",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("min_signal_strength", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("enabled_signal_types", postgresql.JSONB(), nullable=False),
        schema="threat_hunt",
    )
''',
        '''
    op.drop_table("threat_hunt_configurations", schema="threat_hunt")
''',
    )
    mig(
        "0147",
        "0146",
        "threat_hunt_technique_refs",
        '''
    op.create_table(
        "threat_hunt_technique_refs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("candidate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("technique_id", sa.String(32), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        schema="threat_hunt",
    )
    op.create_index("ix_hunt_tech_candidate", "threat_hunt_technique_refs", ["candidate_id"], schema="threat_hunt")
''',
        '''
    op.drop_index("ix_hunt_tech_candidate", table_name="threat_hunt_technique_refs", schema="threat_hunt")
    op.drop_table("threat_hunt_technique_refs", schema="threat_hunt")
''',
    )
    mig(
        "0148",
        "0147",
        "security_graph_m36_nodes",
        '''
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'node_types'
            ) THEN
                INSERT INTO security_graph.node_types(node_type)
                VALUES ('intelligence_suggestion'), ('optimization_model'), ('threat_hunt_candidate')
                ON CONFLICT DO NOTHING;
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                INSERT INTO security_graph.edge_types(edge_type)
                VALUES ('suggested_modification'), ('approved_suggestion'),
                       ('outcome_feedback'), ('generated_detection')
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
                WHERE node_type IN ('intelligence_suggestion', 'optimization_model', 'threat_hunt_candidate');
            END IF;
            IF EXISTS (
                SELECT 1 FROM information_schema.tables
                WHERE table_schema = 'security_graph' AND table_name = 'edge_types'
            ) THEN
                DELETE FROM security_graph.edge_types
                WHERE edge_type IN ('suggested_modification', 'approved_suggestion',
                                    'outcome_feedback', 'generated_detection');
            END IF;
        END $$;
        """
    )
''',
    )
    mig(
        "0149",
        "0148",
        "m36_analytics_projection",
        '''
    op.execute("CREATE SCHEMA IF NOT EXISTS analytics")
    op.create_table(
        "m36_suggestion_metrics",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("suggestion_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("target_type", sa.String(80), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("event_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        schema="analytics",
    )
    op.create_index("ix_m36_metrics_tenant_ts", "m36_suggestion_metrics", ["tenant_id", "event_ts"], schema="analytics")
    op.create_index("ix_m36_metrics_tenant_type", "m36_suggestion_metrics", ["tenant_id", "target_type", "event_ts"], schema="analytics")
''',
        '''
    op.drop_index("ix_m36_metrics_tenant_type", table_name="m36_suggestion_metrics", schema="analytics")
    op.drop_index("ix_m36_metrics_tenant_ts", table_name="m36_suggestion_metrics", schema="analytics")
    op.drop_table("m36_suggestion_metrics", schema="analytics")
''',
    )


def _outbound_acl() -> None:
    # Minimal pending work-item entities in target contexts (ACL only)
    for pkg, fname, item in [
        ("detection", "m36_rule_tuning_proposal_subscriber.py", "PendingRuleTuningItem"),
        ("campaign", "m36_scenario_proposal_subscriber.py", "PendingScenarioItem"),
        ("playbook", "m36_playbook_synthesis_subscriber.py", "PendingSynthesisItem"),
    ]:
        path = SRC / pkg / "infrastructure" / "acl" / fname
        w(
            path,
            f'''"""Outbound ACL subscriber for M36 proposals — ADR-M36-007."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4


@dataclass
class {item}:
    item_id: UUID
    tenant_id: str
    suggestion_id: str
    proposal_payload: dict[str, object]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: str = "pending"


class M36ProposalSubscriber:
    def __init__(self) -> None:
        self.queue: list[{item}] = []

    def handle(
        self,
        tenant_id: str,
        suggestion_id: str,
        proposal_payload: dict[str, object],
    ) -> {item}:
        item = {item}(uuid4(), tenant_id, suggestion_id, dict(proposal_payload))
        self.queue.append(item)
        return item
''',
        )


def _wiring() -> None:
    api_init = ROOT / "src" / "redforge" / "api" / "v1" / "__init__.py"
    text = api_init.read_text()
    if "autonomous_intelligence.api.v1" not in text:
        text = text.replace(
            "from automated_action.api.v1 import router as automated_action_router\n",
            "from autonomous_intelligence.api.v1 import router as autonomous_intelligence_router\n"
            "from automated_action.api.v1 import router as automated_action_router\n"
            "from posture_forecasting.api.v1 import router as posture_forecasting_router\n"
            "from threat_hunt.api.v1 import router as threat_hunt_router\n",
        )
        text = text.replace(
            "router.include_router(playbook_router, tags=[\"playbook\"])\n",
            "router.include_router(playbook_router, tags=[\"playbook\"])\n"
            "router.include_router(autonomous_intelligence_router, tags=[\"autonomous-intelligence\"])\n"
            "router.include_router(posture_forecasting_router, tags=[\"posture-forecasting\"])\n"
            "router.include_router(threat_hunt_router, tags=[\"threat-hunt\"])\n",
        )
        api_init.write_text(text)

    pyproject = ROOT / "pyproject.toml"
    pt = pyproject.read_text()
    if '"autonomous_intelligence"' not in pt:
        pt = pt.replace(
            '"integration_hub" = ["py.typed"]\n',
            '"integration_hub" = ["py.typed"]\n'
            '"autonomous_intelligence" = ["py.typed"]\n'
            '"posture_forecasting" = ["py.typed"]\n'
            '"threat_hunt" = ["py.typed"]\n',
        )
        pt = pt.replace(
            '"playbook", "automated_action", "integration_hub"]',
            '"playbook", "automated_action", "integration_hub", '
            '"autonomous_intelligence", "posture_forecasting", "threat_hunt"]',
        )
        ignore_block = '''
"src/autonomous_intelligence/api/**" = ["B008", "TC001", "TC003"]
"src/autonomous_intelligence/application/**" = ["TC001", "TC003", "TC004"]
"src/autonomous_intelligence/infrastructure/**" = ["TC001", "TC003"]
"src/autonomous_intelligence/domain/exceptions/**" = ["N818"]
"src/autonomous_intelligence/domain/**" = ["TC001", "TC003"]
"src/posture_forecasting/api/**" = ["B008", "TC001", "TC003"]
"src/posture_forecasting/application/**" = ["TC001", "TC003", "TC004"]
"src/posture_forecasting/infrastructure/**" = ["TC001", "TC003"]
"src/posture_forecasting/domain/exceptions/**" = ["N818"]
"src/posture_forecasting/domain/**" = ["TC001", "TC003"]
"src/threat_hunt/api/**" = ["B008", "TC001", "TC003"]
"src/threat_hunt/application/**" = ["TC001", "TC003", "TC004"]
"src/threat_hunt/infrastructure/**" = ["TC001", "TC003"]
"src/threat_hunt/domain/exceptions/**" = ["N818"]
"src/threat_hunt/domain/**" = ["TC001", "TC003"]
'''
        marker = '"src/integration_hub/domain/**" = ["TC001", "TC003"]\n'
        if marker in pt and "src/autonomous_intelligence/api/**" not in pt:
            pt = pt.replace(marker, marker + ignore_block)
        pyproject.write_text(pt)


def _update_migration_tests() -> None:
    path = TESTS / "analytics" / "test_migration_chain.py"
    if path.exists():
        text = path.read_text()
        text = text.replace('assert heads == ["0130"]', 'assert heads == ["0149"]')
        text = text.replace("test_single_head_0113", "test_single_head_0149")
        path.write_text(text)
    w(
        TESTS / "autonomous_intelligence" / "test_migration_chain.py",
        '''from __future__ import annotations

import re
from pathlib import Path

MIG = Path(__file__).resolve().parents[2] / "src" / "redforge" / "infrastructure" / "database" / "migrations" / "versions"


def test_m36_migration_chain_linear() -> None:
    expected = [f"{i:04d}" for i in range(131, 150)]
    revs: dict[str, str | None] = {}
    for f in MIG.glob("01*.py"):
        text = f.read_text()
        rev_m = re.search(r'revision:\\s*str\\s*=\\s*"(\\d+)"', text)
        down_m = re.search(r'down_revision:\\s*str\\s*=\\s*"(\\d+)"', text)
        if rev_m:
            revs[rev_m.group(1)] = down_m.group(1) if down_m else None
    for rev in expected:
        assert rev in revs, f"missing migration {rev}"
    assert revs["0131"] == "0130"
    for i in range(132, 150):
        assert revs[f"{i:04d}"] == f"{i-1:04d}"
    heads = [r for r in revs if r not in set(v for v in revs.values() if v)]
    assert "0149" in heads
''',
    )
    # Extra autonomous tests for coverage
    w(
        TESTS / "autonomous_intelligence" / "test_suggestion_proposal_never_mutates_target_context_directly.py",
        '''from __future__ import annotations

from autonomous_intelligence.domain.services.autonomy_boundary_service import AutonomyBoundaryService
from autonomous_intelligence.domain.exceptions.domain_exceptions import AutonBoundaryViolation
import pytest


def test_suggestion_proposal_never_mutates_target_context_directly() -> None:
    svc = AutonomyBoundaryService()
    for name in ("DetectionRule", "RuleVersion", "ScenarioTemplate", "PlaybookVersion", "Vulnerability"):
        with pytest.raises(AutonBoundaryViolation):
            svc.assert_no_direct_mutation(name)
''',
    )
    w(
        TESTS / "autonomous_intelligence" / "test_more_coverage.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    CreateIntelligenceSuggestion,
)
from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.evidence import (
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId
from autonomous_intelligence.infrastructure.acl.m28_performance_translator import (
    DetectionRulePerformanceReportedPayload,
    M28PerformanceTranslator,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.parametrize("tt", list(SuggestionTargetType))
@pytest.mark.asyncio
async def test_create_all_target_types(tt: SuggestionTargetType) -> None:
    c = AutonomousIntelligenceContainer()
    # ensure confidence meets default
    conf = {
        SuggestionTargetType.DETECTION_RULE_TUNING: 0.80,
        SuggestionTargetType.CAMPAIGN_SCENARIO: 0.70,
        SuggestionTargetType.PLAYBOOK_SYNTHESIS: 0.75,
        SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: 0.65,
    }[tt]
    dto = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            uuid4(),
            tt.value.split("_")[0],
            None,
            tt.value,
            {},
            "m",
            1,
            conf,
            ("s",),
            "rationale",
            ("system",),
        )
    )
    assert dto.target_type == tt.value


@pytest.mark.asyncio
async def test_kill_switch_blocks_generation() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    policy = await c.policies.get_or_create_default(TenantId(tenant))
    policy.activate_kill_switch()
    await c.policies.save(policy, TenantId(tenant))
    with pytest.raises(DomainInvariantViolation):
        await c.app.create_suggestion(
            CreateIntelligenceSuggestion(
                tenant,
                "detection",
                None,
                "detection_rule_tuning",
                {},
                "m",
                1,
                0.9,
                (),
                "x",
                ("system",),
            )
        )


def test_withdraw() -> None:
    tenant = TenantId(uuid4())
    s = IntelligenceSuggestion.create(
        tenant,
        SuggestionTargetRef(
            target_context="detection",
            target_id=None,
            target_type=SuggestionTargetType.DETECTION_RULE_TUNING,
            proposed_change_payload={},
        ),
        SuggestionEvidence(
            model_id="m",
            model_version=1,
            confidence_score=0.9,
            supporting_signal_refs=(),
            rationale_summary="r",
            generated_at=datetime.now(UTC),
        ),
    )
    s.withdraw(tenant, "retrain")
    assert s.status.value == "withdrawn"


def test_acl_translators() -> None:
    sig = M28PerformanceTranslator().translate(
        DetectionRulePerformanceReportedPayload("t", "r1", "HIGH", {"fp": 0.2})
    )
    assert sig is not None


def test_policy_default() -> None:
    p = AutonomousOperationsPolicy.default(TenantId(uuid4()))
    assert p.allows(SuggestionTargetType.PLAYBOOK_SYNTHESIS)
''',
    )

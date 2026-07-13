"""Unit tests for CampaignEngine (application/campaigns/campaign_engine.py).

Uses fakes for all collaborators — no real ValidationService, no DB.

Focus:
  - Fan-out logic (sequential vs parallel, semaphore bounding)
  - Progress recording (completed targets, failed targets)
  - Retry behaviour
  - Drift detection integration
  - PipelineExecutor.trigger() contract
  - Post-commit isolation: KG / event publisher failures don't kill campaign
  - Pause/resume/cancel
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from redforge.application.campaigns.campaign_engine import (
    CampaignEngine,
    CampaignRequest,
    _compute_metrics,
)
from redforge.application.campaigns.knowledge_projector import (
    CampaignKnowledgeGraphProjector,
)
from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.application.validation_service import (
    ValidationServiceRequest,
    ValidationServiceResult,
)
from redforge.domain.campaigns.entity import Campaign
from redforge.domain.campaigns.value_objects import (
    CampaignConfiguration,
    CampaignStatus,
    CampaignType,
    TargetResult,
)
from redforge.domain.policies.value_objects import ExecutionStrategy
from redforge.shared.identifiers import EntityId

# ─── Fakes ────────────────────────────────────────────────────────────────────


class _FakeValidationService:
    """Fake ValidationService. Configurable per target_id."""

    def __init__(
        self,
        results: dict[str, str] | None = None,  # target_id → "completed" | "failed"
        raise_for: set[str] | None = None,       # target_ids that raise an exception
    ) -> None:
        self._results = results or {}
        self._raise_for = raise_for or set()
        self.calls: list[ValidationServiceRequest] = []

    async def execute(self, request: ValidationServiceRequest) -> ValidationServiceResult:
        self.calls.append(request)
        tid = request.target_id
        if tid in self._raise_for:
            raise RuntimeError(f"executor error for {tid}")
        status = self._results.get(tid, "completed")
        return _make_vs_result(request.target_id, status=status)


def _make_vs_result(
    target_id: str, status: str = "completed", findings: int = 1
) -> ValidationServiceResult:
    from unittest.mock import MagicMock

    from redforge.application.runtime.orchestrator import ExecutionResult
    mock_exec_result = MagicMock(spec=ExecutionResult)
    return ValidationServiceResult(
        run_id=str(EntityId.generate()),
        organization_id="org-1",
        target_id=target_id,
        status=status,
        total_attacks=4,
        passed=3 if status == "completed" else 0,
        failed=findings if status == "completed" else 0,
        errors=0,
        inconclusive=0,
        duration_ms=200,
        evidence_ids=[str(EntityId.generate())],
        finding_ids=[str(EntityId.generate())] * (findings if status == "completed" else 0),
        risk_incidents=[],
        kg_nodes_added=1,
        execution_result=mock_exec_result,
        failure_reason=None if status == "completed" else "validation failed",
    )


class _FakeCampaignRepository:
    def __init__(self) -> None:
        self._store: dict[str, Campaign] = {}
        self.save_count = 0

    async def save(self, campaign: Campaign) -> None:
        self._store[str(campaign.id)] = campaign
        self.save_count += 1

    async def get(self, campaign_id: str) -> Campaign | None:
        return self._store.get(campaign_id)


class _FakeTargetSelector:
    def __init__(self, target_ids: list[str] | None = None) -> None:
        self._ids = target_ids or []

    async def select(self, organization_id: str, policy_id: str) -> list[str]:
        return self._ids


class _FakeEventPublisher:
    def __init__(self) -> None:
        self.published: list[object] = []

    async def publish(self, events: Sequence[object]) -> None:
        self.published.extend(events)


class _BrokenEventPublisher:
    async def publish(self, events: Sequence[object]) -> None:
        raise RuntimeError("broker down")


class _FakeDecisionResult:
    def __init__(self, decision: str, reason_code: str = "ALLOWED_BY_ACTIVE_AUTHORIZATION") -> None:
        self.decision = decision
        self.reason_code = reason_code
        self.decision_id = str(EntityId.generate())


class _FakeExecutionPolicyService:
    """Fake ExecutionPolicyPort. Defaults to ALLOW — tests that need to
    prove the gate blocks execution pass decision="deny" or
    "approval_required" explicitly."""

    def __init__(self, decision: str = "allow") -> None:
        self._decision = decision
        self.calls: list[dict[str, object]] = []

    async def evaluate(
        self, *, organization_id: str, actor_user_id: str, action_class: str,
        entity_refs: list[tuple[str, str]],
    ) -> _FakeDecisionResult:
        self.calls.append({
            "organization_id": organization_id, "actor_user_id": actor_user_id,
            "action_class": action_class, "entity_refs": entity_refs,
        })
        return _FakeDecisionResult(self._decision)


class _FakeBaselinePort:
    def __init__(
        self,
        findings: dict[str, int] | None = None,
        rates: dict[str, float] | None = None,
    ) -> None:
        self._findings = findings or {}
        self._rates = rates or {}

    async def get_findings_summary(self, campaign_id: str) -> dict[str, int]:
        return self._findings

    async def get_vulnerability_rates(self, campaign_id: str) -> dict[str, float]:
        return self._rates


# ─── Helpers ──────────────────────────────────────────────────────────────────

T1 = str(EntityId.generate())
T2 = str(EntityId.generate())
T3 = str(EntityId.generate())

_ORG = str(EntityId.generate())
_POLICY = str(EntityId.generate())


def _request(
    target_ids: list[str] | None = None,
    strategy: ExecutionStrategy = ExecutionStrategy.SEQUENTIAL,
    configuration: CampaignConfiguration | None = None,
    baseline_campaign_id: str | None = None,
    actor_user_id: str = "actor-1",
) -> CampaignRequest:
    tids = target_ids or [T1, T2]
    return CampaignRequest(
        organization_id=_ORG,
        policy_id=_POLICY,
        campaign_type=CampaignType.MANUAL,
        target_endpoint_map={tid: f"https://api.example.com/{tid}" for tid in tids},
        target_provider_map={tid: "openai" for tid in tids},
        target_name_map={tid: f"Target-{tid[:8]}" for tid in tids},
        target_model_map={tid: "gpt-4o" for tid in tids},
        target_system_prompt_map={tid: "You are a helpful assistant." for tid in tids},
        attack_categories=frozenset(["prompt_injection"]),
        correlation_id="corr-test",
        actor_user_id=actor_user_id,
        execution_strategy=strategy,
        configuration=configuration,
        baseline_campaign_id=baseline_campaign_id,
    )


def _engine(
    vs: _FakeValidationService | None = None,
    repo: _FakeCampaignRepository | None = None,
    selector: _FakeTargetSelector | None = None,
    event_publisher=None,
    baseline_port=None,
    knowledge_projector=None,
    execution_policy_service: _FakeExecutionPolicyService | None = None,
) -> tuple[CampaignEngine, _FakeCampaignRepository]:
    r = repo or _FakeCampaignRepository()
    return (
        CampaignEngine(
            validation_service=vs or _FakeValidationService(),
            target_selector=selector or _FakeTargetSelector(),
            campaign_repository=r,
            execution_policy_service=execution_policy_service or _FakeExecutionPolicyService(),
            event_publisher=event_publisher,
            baseline_port=baseline_port,
            knowledge_projector=knowledge_projector,
        ),
        r,
    )


# ─── Tests ────────────────────────────────────────────────────────────────────


class TestExecuteCampaignBasic:
    async def test_completes_with_all_targets_succeeded(self) -> None:
        eng, _repo = _engine()
        result = await eng.execute_campaign(_request([T1, T2]))
        assert result.status == "completed"
        assert result.successful_targets == 2
        assert result.failed_targets == 0

    async def test_campaign_persisted(self) -> None:
        eng, repo = _engine()
        result = await eng.execute_campaign(_request([T1]))
        campaign = await repo.get(result.campaign_id)
        assert campaign is not None
        assert campaign.status == CampaignStatus.COMPLETED

    async def test_metrics_attached(self) -> None:
        eng, repo = _engine()
        result = await eng.execute_campaign(_request([T1, T2]))
        campaign = await repo.get(result.campaign_id)
        assert campaign.metrics is not None
        assert campaign.metrics.total_targets == 2

    async def test_progress_complete_after_all_targets(self) -> None:
        eng, repo = _engine()
        result = await eng.execute_campaign(_request([T1, T2]))
        campaign = await repo.get(result.campaign_id)
        assert campaign.progress.is_complete

    async def test_total_findings_aggregated(self) -> None:
        vs = _FakeValidationService()
        eng, _ = _engine(vs=vs)
        result = await eng.execute_campaign(_request([T1, T2]))
        assert result.total_findings == 2  # 1 finding per target


class TestTargetFailure:
    async def test_one_failed_target_does_not_abort_campaign(self) -> None:
        vs = _FakeValidationService(results={T1: "failed", T2: "completed"})
        eng, _repo = _engine(vs=vs)
        result = await eng.execute_campaign(_request([T1, T2]))
        assert result.status == "completed"
        assert result.failed_targets == 1
        assert result.successful_targets == 1

    async def test_executor_exception_records_failed_target(self) -> None:
        vs = _FakeValidationService(raise_for={T1})
        eng, _repo = _engine(vs=vs)
        result = await eng.execute_campaign(_request([T1, T2]))
        assert result.failed_targets == 1
        assert result.status == "completed"

    async def test_all_failed_still_completes_campaign(self) -> None:
        vs = _FakeValidationService(results={T1: "failed", T2: "failed"})
        eng, _repo = _engine(vs=vs)
        result = await eng.execute_campaign(_request([T1, T2]))
        assert result.status == "completed"
        assert result.failed_targets == 2


class TestRetry:
    async def test_retries_failed_target_once(self) -> None:
        attempt = {"count": 0}

        class _RetryVS:
            calls: list[ValidationServiceRequest] = []  # noqa: RUF012
            async def execute(self, req: ValidationServiceRequest) -> ValidationServiceResult:
                self.calls.append(req)
                attempt["count"] += 1
                # fail first attempt, succeed on retry
                status = "failed" if attempt["count"] == 1 else "completed"
                return _make_vs_result(req.target_id, status=status)

        retry_vs = _RetryVS()
        cfg = CampaignConfiguration(retry_failed_targets=True, max_retries_per_target=1)
        eng, _ = _engine(vs=retry_vs)
        result = await eng.execute_campaign(_request([T1], configuration=cfg))
        assert result.successful_targets == 1
        assert attempt["count"] == 2

    async def test_no_retry_when_disabled(self) -> None:
        vs = _FakeValidationService(results={T1: "failed"})
        cfg = CampaignConfiguration(retry_failed_targets=False)
        eng, _ = _engine(vs=vs)
        result = await eng.execute_campaign(_request([T1], configuration=cfg))
        assert len(vs.calls) == 1
        assert result.failed_targets == 1


class TestExecutionStrategy:
    async def test_sequential_strategy_executes_all_targets(self) -> None:
        vs = _FakeValidationService()
        eng, _ = _engine(vs=vs)
        result = await eng.execute_campaign(
            _request([T1, T2, T3], strategy=ExecutionStrategy.SEQUENTIAL)
        )
        assert result.successful_targets == 3
        # Sequential means one correlation_id per target
        assert len(vs.calls) == 3

    async def test_parallel_strategy_executes_all_targets(self) -> None:
        vs = _FakeValidationService()
        eng, _ = _engine(vs=vs)
        result = await eng.execute_campaign(
            _request([T1, T2, T3], strategy=ExecutionStrategy.PARALLEL)
        )
        assert result.successful_targets == 3

    async def test_semaphore_limits_concurrent_targets(self) -> None:
        """When max_concurrent_targets=1 and PARALLEL, targets run serially
        (semaphore allows only one at a time). All targets still complete."""
        vs = _FakeValidationService()
        cfg = CampaignConfiguration(max_concurrent_targets=1)
        eng, _ = _engine(vs=vs)
        result = await eng.execute_campaign(
            _request([T1, T2, T3], strategy=ExecutionStrategy.PARALLEL, configuration=cfg)
        )
        assert result.successful_targets == 3


class TestDriftDetection:
    async def test_drift_summary_attached_when_baseline_provided(self) -> None:
        baseline_id = str(EntityId.generate())
        baseline_port = _FakeBaselinePort(
            findings={T1: 1, T2: 0},
            rates={T1: 0.25, T2: 0.0},
        )
        eng, repo = _engine(baseline_port=baseline_port)
        result = await eng.execute_campaign(
            _request([T1, T2], baseline_campaign_id=baseline_id)
        )
        campaign = await repo.get(result.campaign_id)
        assert campaign.drift_summary is not None

    async def test_no_drift_when_no_baseline(self) -> None:
        eng, repo = _engine()
        result = await eng.execute_campaign(_request([T1]))
        campaign = await repo.get(result.campaign_id)
        assert campaign.drift_summary is None

    async def test_regression_detected_in_result(self) -> None:
        baseline_id = str(EntityId.generate())
        # Baseline had 0 findings per target; current has 1 each → regression
        baseline_port = _FakeBaselinePort(
            findings={T1: 0, T2: 0},
            rates={T1: 0.0, T2: 0.0},
        )
        eng, _repo = _engine(baseline_port=baseline_port)
        result = await eng.execute_campaign(
            _request([T1, T2], baseline_campaign_id=baseline_id)
        )
        assert result.regression_detected is True

    async def test_baseline_port_error_does_not_abort_campaign(self) -> None:
        class _BrokenBaselinePort:
            async def get_findings_summary(self, _: str) -> dict:
                raise RuntimeError("baseline store unavailable")
            async def get_vulnerability_rates(self, _: str) -> dict:
                raise RuntimeError("baseline store unavailable")

        eng, repo = _engine(baseline_port=_BrokenBaselinePort())
        result = await eng.execute_campaign(
            _request([T1], baseline_campaign_id=str(EntityId.generate()))
        )
        assert result.status == "completed"
        campaign = await repo.get(result.campaign_id)
        assert campaign.drift_summary is None


class TestPostCommitIsolation:
    async def test_broken_event_publisher_does_not_fail_campaign(self) -> None:
        eng, _repo = _engine(event_publisher=_BrokenEventPublisher())
        result = await eng.execute_campaign(_request([T1]))
        assert result.status == "completed"

    async def test_events_published_on_success(self) -> None:
        pub = _FakeEventPublisher()
        eng, _ = _engine(event_publisher=pub)
        await eng.execute_campaign(_request([T1]))
        assert len(pub.published) > 0

    async def test_knowledge_graph_projected_on_completion(self) -> None:
        graph = KnowledgeGraph()
        projector = CampaignKnowledgeGraphProjector(graph)
        eng, _ = _engine(knowledge_projector=projector)
        result = await eng.execute_campaign(_request([T1]))
        nodes = graph.query_by_type(NodeType.CAMPAIGN)
        assert len(nodes) == 1
        assert nodes[0].node_id == result.campaign_id

    async def test_broken_kg_projector_does_not_fail_campaign(self) -> None:
        class _BrokenProjector:
            def project_campaign(self, _: Campaign) -> int:
                raise RuntimeError("graph store unavailable")

        eng, _ = _engine(knowledge_projector=_BrokenProjector())
        result = await eng.execute_campaign(_request([T1]))
        assert result.status == "completed"


class TestPipelineExecutorProtocol:
    async def test_trigger_returns_campaign_id_string(self) -> None:
        selector = _FakeTargetSelector(target_ids=[T1, T2])
        eng, repo = _engine(selector=selector)
        campaign_id = await eng.trigger(
            organization_id=_ORG,
            target_id=T1,
            policy_id=_POLICY,
        )
        assert isinstance(campaign_id, str)
        campaign = await repo.get(campaign_id)
        assert campaign is not None
        assert campaign.status == CampaignStatus.PENDING

    async def test_trigger_falls_back_to_hint_target_when_selector_empty(self) -> None:
        selector = _FakeTargetSelector(target_ids=[])
        eng, repo = _engine(selector=selector)
        campaign_id = await eng.trigger(
            organization_id=_ORG,
            target_id=T1,
            policy_id=_POLICY,
        )
        campaign = await repo.get(campaign_id)
        assert EntityId.from_string(T1) in campaign.target_ids


class TestComputeMetrics:
    def test_all_successful(self) -> None:
        results = [
            TargetResult(EntityId.generate(), "r1", "completed", 2, 0.5, 100),
            TargetResult(EntityId.generate(), "r2", "completed", 1, 0.25, 200),
        ]
        m = _compute_metrics(results, 300)
        assert m.total_targets == 2
        assert m.successful_targets == 2
        assert m.failed_targets == 0
        assert m.total_findings == 3
        assert m.mean_vulnerability_rate == pytest.approx(0.375)

    def test_empty_results(self) -> None:
        m = _compute_metrics([], 0)
        assert m.total_targets == 0
        assert m.mean_vulnerability_rate == 0.0

    def test_all_failed_mean_rate_is_zero(self) -> None:
        results = [
            TargetResult(EntityId.generate(), "", "failed", 0, 0.0, 0, "err"),
        ]
        m = _compute_metrics(results, 0)
        assert m.mean_vulnerability_rate == 0.0
        assert m.failed_targets == 1


class TestM10ExecutionPolicyGate:
    """CampaignEngine is the only real active-execution dispatch path in
    the platform (M10 execution bypass review) — every dispatch must be
    gated by ExecutionPolicyPort.evaluate() before any Campaign
    aggregate is created."""

    def test_cannot_construct_without_execution_policy_service(self) -> None:
        """Regression test: no caller can build a working CampaignEngine
        without wiring a real ExecutionPolicyPort — the parameter has no
        default, so omitting it is a TypeError, not a silently-permissive
        engine."""
        with pytest.raises(TypeError):
            CampaignEngine(  # type: ignore[call-arg]
                validation_service=_FakeValidationService(),
                target_selector=_FakeTargetSelector(),
                campaign_repository=_FakeCampaignRepository(),
            )

    async def test_deny_blocks_execution_and_creates_no_campaign(self) -> None:
        from redforge.domain.authorization.exceptions import ExecutionNotAuthorizedError

        policy = _FakeExecutionPolicyService(decision="deny")
        eng, repo = _engine(execution_policy_service=policy)

        with pytest.raises(ExecutionNotAuthorizedError):
            await eng.execute_campaign(_request([T1, T2]))

        assert repo.save_count == 0
        assert len(policy.calls) == 1
        assert policy.calls[0]["action_class"] == "active_validation"
        assert set(policy.calls[0]["entity_refs"]) == {("ai_target", T1), ("ai_target", T2)}

    async def test_approval_required_blocks_execution(self) -> None:
        from redforge.domain.authorization.exceptions import ExecutionNotAuthorizedError

        policy = _FakeExecutionPolicyService(decision="approval_required")
        eng, repo = _engine(execution_policy_service=policy)

        with pytest.raises(ExecutionNotAuthorizedError) as exc_info:
            await eng.execute_campaign(_request([T1]))

        assert exc_info.value.decision == "approval_required"
        assert repo.save_count == 0

    async def test_allow_permits_execution(self) -> None:
        policy = _FakeExecutionPolicyService(decision="allow")
        eng, _repo = _engine(execution_policy_service=policy)
        result = await eng.execute_campaign(_request([T1, T2]))
        assert result.status == "completed"

    async def test_trigger_is_also_gated(self) -> None:
        from redforge.domain.authorization.exceptions import ExecutionNotAuthorizedError

        policy = _FakeExecutionPolicyService(decision="deny")
        selector = _FakeTargetSelector(target_ids=[T1])
        eng, repo = _engine(selector=selector, execution_policy_service=policy)

        with pytest.raises(ExecutionNotAuthorizedError):
            await eng.trigger(organization_id=_ORG, target_id=T1, policy_id=_POLICY)

        assert policy.calls[0]["actor_user_id"] == "system:scheduler"
        assert repo.save_count == 0

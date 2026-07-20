"""CSPM evaluation pipeline — filter policies and run PolicyEvaluationEngine."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from redforge.domain.cloud_security.cspm.entities import EvaluationResult, FindingEvidence
from redforge.domain.cloud_security.cspm.policy import CSPMPolicy
from redforge.domain.cloud_security.cspm.value_objects import ResourceSnapshot
from redforge.domain.cloud_security.policy_engine.evaluator import (
    ConditionOutcome,
    PolicyEvaluationEngine,
)


@dataclass(frozen=True, slots=True)
class EvaluationResults:
    results: list[EvaluationResult]
    policies_evaluated: int
    violations: int
    passes: int
    duration_ms: int


def _evaluate_one(
    engine: PolicyEvaluationEngine,
    policy: CSPMPolicy,
    snapshot_dict: dict[str, Any],
    cloud_asset_id: str,
) -> EvaluationResult:
    started = time.perf_counter()
    outcome: ConditionOutcome = engine.evaluate(policy.rule, snapshot_dict)
    duration_ms = int((time.perf_counter() - started) * 1000)
    # matched=True means violation (finding should open) => passed=False
    passed = not outcome.matched
    evidence = (
        ()
        if passed
        else (
            FindingEvidence.create(
                path=outcome.path,
                expected=outcome.expected,
                actual=outcome.actual,
                message=outcome.message,
            ),
        )
    )
    return EvaluationResult(
        policy_id=str(policy.id),
        rule_id=str(policy.rule_id),
        cloud_asset_id=cloud_asset_id,
        passed=passed,
        severity=policy.severity.value,
        title=policy.title,
        message=outcome.message,
        evidence=evidence,
        duration_ms=duration_ms,
    )


class EvaluationPipeline:
    """Orchestrates deterministic, batched policy evaluation for one snapshot."""

    def __init__(
        self,
        engine: PolicyEvaluationEngine | None = None,
        *,
        batch_size: int = 8,
        max_workers: int = 4,
    ) -> None:
        self._engine = engine or PolicyEvaluationEngine()
        self._batch_size = max(1, batch_size)
        self._max_workers = max(1, max_workers)

    def filter_policies(
        self,
        policies: list[CSPMPolicy],
        *,
        provider_type: str,
        asset_type: str,
        policy_ids: tuple[str, ...] = (),
    ) -> list[CSPMPolicy]:
        filtered = [
            p
            for p in policies
            if p.applies_to(provider_type=provider_type, asset_type=asset_type)
        ]
        if policy_ids:
            wanted = set(policy_ids)
            filtered = [p for p in filtered if str(p.id) in wanted]
        return sorted(filtered, key=lambda p: str(p.id))

    async def evaluate_snapshot(
        self,
        *,
        snapshot: ResourceSnapshot,
        policies: list[CSPMPolicy],
        policy_ids: tuple[str, ...] = (),
    ) -> EvaluationResults:
        applicable = self.filter_policies(
            policies,
            provider_type=snapshot.provider_type,
            asset_type=snapshot.asset_type,
            policy_ids=policy_ids,
        )
        snapshot_dict = snapshot.to_dict()
        started = time.perf_counter()
        results: list[EvaluationResult] = []
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            for offset in range(0, len(applicable), self._batch_size):
                batch = applicable[offset : offset + self._batch_size]
                batch_results = await asyncio.gather(
                    *[
                        loop.run_in_executor(
                            pool,
                            _evaluate_one,
                            self._engine,
                            policy,
                            snapshot_dict,
                            snapshot.cloud_asset_id,
                        )
                        for policy in batch
                    ]
                )
                results.extend(batch_results)
        duration_ms = int((time.perf_counter() - started) * 1000)
        violations = sum(1 for r in results if not r.passed)
        passes = sum(1 for r in results if r.passed)
        return EvaluationResults(
            results=results,
            policies_evaluated=len(results),
            violations=violations,
            passes=passes,
            duration_ms=duration_ms,
        )

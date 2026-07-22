"""Dry-run simulation for playbook versions."""

from __future__ import annotations

from dataclasses import dataclass

from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.value_objects.enums import TestOutcome


@dataclass(frozen=True, slots=True)
class DryRunResult:
    outcome: TestOutcome
    steps_tested: int
    steps_passed: int
    coverage_paths: list[str]
    duration_ms: int


class PlaybookDryRunService:
    def run(self, version: PlaybookVersion) -> DryRunResult:
        steps = sorted(version.action_steps, key=lambda s: s.step_number)
        if not steps:
            return DryRunResult(TestOutcome.FAILED, 0, 0, [], 1)
        paths: list[str] = []
        passed = 0
        for step in steps:
            # Dry-run validates structure: connector type present, no secret keys in params
            secret_keys = {"api_key", "secret", "password", "token", "private_key", "certificate"}
            if secret_keys.intersection(step.parameters):
                paths.append(f"step:{step.step_number}:secret_rejected")
                continue
            if not step.action_type:
                paths.append(f"step:{step.step_number}:missing_action")
                continue
            paths.append(f"step:{step.step_number}:ok")
            passed += 1
        tested = len(steps)
        if passed == tested:
            outcome = TestOutcome.PASSED
        elif passed == 0:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.PARTIAL
        return DryRunResult(outcome, tested, passed, paths, max(1, tested * 5))

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PlaybookDTO:
    playbook_id: str
    tenant_id: str
    name: str
    description: str
    status: str
    current_version_number: int
    max_impact_level: str
    created_by: str
    approved_by: list[str]


@dataclass(frozen=True, slots=True)
class PlaybookVersionDTO:
    version_id: str
    playbook_id: str
    version_number: int
    status: str
    content_hash: str
    step_count: int


@dataclass(frozen=True, slots=True)
class PlaybookTestResultDTO:
    test_id: str
    playbook_id: str
    version_id: str
    content_hash_at_test: str
    outcome: str
    steps_tested: int
    steps_passed: int


@dataclass(frozen=True, slots=True)
class AutomationPolicyDTO:
    tenant_id: str
    kill_switch_state: str
    kill_switch_triggered_by: str | None
    max_concurrent_executions: int
    max_actions_per_hour: int

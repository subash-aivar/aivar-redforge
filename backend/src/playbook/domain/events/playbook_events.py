"""Frozen playbook domain events (M35)."""

from __future__ import annotations

from dataclasses import dataclass

from playbook.domain.events.base import BasePlaybookEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookCreated(BasePlaybookEvent):
    playbook_id: str
    name: str
    created_by: str
    created_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookVersionPublished(BasePlaybookEvent):
    playbook_id: str
    version_id: str
    version_number: int
    content_hash: str
    published_by: str
    published_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookApproved(BasePlaybookEvent):
    playbook_id: str
    version_number: int
    max_impact_level: str
    approved_by: list[str]
    approved_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookDeprecated(BasePlaybookEvent):
    playbook_id: str
    deprecated_by: str
    deprecated_at: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookTestCompleted(BasePlaybookEvent):
    playbook_id: str
    test_id: str
    version_id: str
    content_hash_at_test: str
    outcome: str
    steps_tested: int
    steps_passed: int
    executed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookTriggered(BasePlaybookEvent):
    playbook_id: str
    version_number: int
    source_context: str
    source_event_id: str
    triggered_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationKillSwitchActivated(BasePlaybookEvent):
    activated_by: str
    activated_at: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationKillSwitchReset(BasePlaybookEvent):
    reset_by: str
    reset_at: str

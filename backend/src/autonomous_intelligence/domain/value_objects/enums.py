"""Frozen enums for autonomous_intelligence (M36)."""

from __future__ import annotations

from enum import StrEnum


class SuggestionStatus(StrEnum):
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


class SuggestionTargetType(StrEnum):
    DETECTION_RULE_TUNING = "detection_rule_tuning"
    CAMPAIGN_SCENARIO = "campaign_scenario"
    PLAYBOOK_SYNTHESIS = "playbook_synthesis"
    VULNERABILITY_PRIORITY_ADJUSTMENT = "vulnerability_priority_adjustment"


class ModelStatus(StrEnum):
    TRAINING = "training"
    VALIDATING = "validating"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"
    FAILED = "failed"


class OutcomeType(StrEnum):
    MEASURABLE = "measurable"
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"


class SuggestionPriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SuggestionCategory(StrEnum):
    DETECTION = "detection"
    OFFENSIVE = "offensive"
    DEFENSIVE = "defensive"
    VULNERABILITY = "vulnerability"

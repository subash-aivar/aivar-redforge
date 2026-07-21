"""Scenario bounded context enumerations."""

from __future__ import annotations

from enum import StrEnum


class ScenarioTemplateState(StrEnum):
    DRAFT = "Draft"
    PUBLISHED = "Published"
    DEPRECATED = "Deprecated"
    ARCHIVED = "Archived"

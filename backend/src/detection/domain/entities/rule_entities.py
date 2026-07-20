"""Owned entities of the DetectionRule aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from detection.domain.exceptions.domain_exceptions import InvalidArgument, RuleVersionImmutable
from detection.domain.value_objects.enums import TestResultStatus

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.value_objects.identifiers import (
        MitreAttackMappingId,
        RuleTestCaseId,
        RuleTestResultId,
        RuleVersionId,
    )
    from detection.domain.value_objects.keys import MitreTechniqueId, RuleSemVer
    from detection.domain.value_objects.rule_logic import RuleLogic


@dataclass
class RuleVersion:
    """Immutable snapshot of rule logic + metadata at a semantic version."""

    version_id: RuleVersionId
    semver: RuleSemVer
    logic: RuleLogic
    change_summary: str
    published_at: datetime
    published_by: str
    _locked: bool = True

    def __post_init__(self) -> None:
        if not self.change_summary.strip():
            raise InvalidArgument("RuleVersion", "change_summary required")
        if not self.published_by.strip():
            raise InvalidArgument("RuleVersion", "published_by required")

    def assert_immutable(self) -> None:
        if self._locked:
            raise RuleVersionImmutable(str(self.semver))


@dataclass
class RuleTestCase:
    test_case_id: RuleTestCaseId
    name: str
    input_payload: dict[str, Any]
    expected_match: bool
    description: str | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise InvalidArgument("RuleTestCase", "name required")


@dataclass
class RuleTestResult:
    result_id: RuleTestResultId
    test_case_id: RuleTestCaseId
    status: TestResultStatus
    duration_ms: int
    recorded_at: datetime
    message: str | None = None
    rule_version: str | None = None

    def __post_init__(self) -> None:
        if self.duration_ms < 0:
            raise InvalidArgument("RuleTestResult", "duration_ms must be >= 0")


@dataclass
class MitreAttackMapping:
    mapping_id: MitreAttackMappingId
    tactic: str
    technique: MitreTechniqueId
    sub_technique: MitreTechniqueId | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if not self.tactic.strip():
            raise InvalidArgument("MitreAttackMapping", "tactic required")

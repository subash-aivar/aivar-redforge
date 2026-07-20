"""PackRule and PackVersion entities for DetectionPack aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from detection.domain.exceptions.domain_exceptions import InvalidArgument

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.value_objects.identifiers import PackRuleId, PackVersionId
    from detection.domain.value_objects.keys import RuleSemVer


@dataclass(slots=True)
class PackRule:
    """Membership linking a DetectionRule at a specific version into the pack."""

    pack_rule_id: PackRuleId
    rule_id: str
    rule_version: RuleSemVer | None
    added_at: datetime
    optional: bool = False

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise InvalidArgument("PackRule.rule_id", "required")
        self.rule_id = self.rule_id.strip()


@dataclass(slots=True)
class PackVersion:
    """Immutable snapshot of pack rule membership at a semantic version."""

    pack_version_id: PackVersionId
    version: RuleSemVer
    rule_snapshots: tuple[tuple[str, str | None], ...]
    released_at: datetime
    release_notes: str = ""

    def __post_init__(self) -> None:
        self.rule_snapshots = tuple(self.rule_snapshots)
        self.release_notes = (self.release_notes or "")[:4096]

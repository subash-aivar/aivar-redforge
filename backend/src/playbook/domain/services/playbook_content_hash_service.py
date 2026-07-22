"""SHA-256 content hashing — ADR-M35-005 / C5."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playbook.domain.aggregates.playbook_version import PlaybookVersion


class PlaybookContentHashService:
    def canonical_json(self, version: PlaybookVersion) -> bytes:
        payload = {
            "action_steps": [
                {
                    "action_type": s.action_type,
                    "connector_type": s.connector_type.value,
                    "impact_level": s.impact_level.value,
                    "max_execution_seconds": s.max_execution_seconds,
                    "parameters": s.parameters,
                    "rollback_definition": (
                        {
                            "is_reversible": s.rollback_definition.is_reversible,
                            "max_rollback_window_hours": (
                                s.rollback_definition.max_rollback_window_hours
                            ),
                            "rollback_action_type": s.rollback_definition.rollback_action_type,
                            "rollback_connector_type": (
                                s.rollback_definition.rollback_connector_type.value
                            ),
                        }
                        if s.rollback_definition
                        else None
                    ),
                    "step_number": s.step_number,
                    "target_selector": s.target_selector.expression,
                }
                for s in sorted(version.action_steps, key=lambda x: x.step_number)
            ],
            "trigger_configs": [
                {
                    "asset_tag_filter": t.asset_tag_filter,
                    "rate_limit_max_invocations": t.rate_limit_max_invocations,
                    "rate_limit_window_seconds": t.rate_limit_window_seconds,
                    "severity_threshold": t.severity_threshold,
                    "source_context": t.source_context.value,
                    "trigger_type": t.trigger_type,
                }
                for t in version.trigger_configs
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute(self, version: PlaybookVersion) -> str:
        return hashlib.sha256(self.canonical_json(version)).hexdigest()

"""Schema validation — ValidateRuleAgainstSchema domain service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from detection.domain.providers.taxonomy import FIELD_REGISTRY
from detection.domain.value_objects.telemetry import (
    SchemaValidationIssue,
    SchemaValidationResult,
)

if TYPE_CHECKING:
    from detection.domain.aggregates.telemetry_source import TelemetrySource
    from detection.domain.value_objects.rule_logic import RuleLogic
    from detection.domain.value_objects.telemetry import SourceSchema


class SchemaValidator:
    """Validates RuleLogic field references against a SourceSchema."""

    def validate(
        self,
        logic: RuleLogic,
        schema: SourceSchema,
        *,
        enforce_taxonomy: bool = True,
    ) -> SchemaValidationResult:
        schema_paths = schema.field_paths()
        requested = {ref.path for ref in logic.normalized_field_refs}
        if not requested:
            for cond in logic.conditions:
                for ref in cond.collect_field_refs():
                    requested.add(ref.path)

        missing = sorted(path for path in requested if path not in schema_paths)
        unsupported: list[str] = []
        issues: list[SchemaValidationIssue] = []

        for path in sorted(requested):
            if enforce_taxonomy and not FIELD_REGISTRY.contains(path):
                unsupported.append(path)
                issues.append(
                    SchemaValidationIssue(
                        field_path=path,
                        issue_type="unsupported_field",
                        message=f"Field {path} is not in the normalized taxonomy",
                    )
                )
            elif path not in schema_paths:
                issues.append(
                    SchemaValidationIssue(
                        field_path=path,
                        issue_type="missing_field",
                        message=f"Field {path} not present in source schema "
                        f"{schema.schema_version}",
                    )
                )

        version_ok = bool(schema.schema_version.strip())
        if not version_ok:
            issues.append(
                SchemaValidationIssue(
                    field_path="",
                    issue_type="version_incompatible",
                    message="Source schema version is empty",
                )
            )

        is_valid = not missing and not unsupported and version_ok
        return SchemaValidationResult(
            is_valid=is_valid,
            missing_fields=tuple(missing),
            unsupported_fields=tuple(sorted(set(unsupported))),
            issues=tuple(issues),
            schema_version=schema.schema_version,
            compatible=is_valid,
        )

    def validate_against_source(
        self,
        logic: RuleLogic,
        source: TelemetrySource,
        *,
        enforce_taxonomy: bool = True,
    ) -> SchemaValidationResult:
        return self.validate(
            logic,
            source.schema,
            enforce_taxonomy=enforce_taxonomy,
        )


def validate_rule_against_schema(
    logic: RuleLogic,
    schema: SourceSchema,
    *,
    enforce_taxonomy: bool = True,
) -> SchemaValidationResult:
    return SchemaValidator().validate(
        logic, schema, enforce_taxonomy=enforce_taxonomy
    )

"""Closed enums for the siem_detection bounded context (M37 §5)."""

from __future__ import annotations

from enum import StrEnum


class DetectionRuleStatus(StrEnum):
    """Rule lifecycle (M37 §5) — reuses the registry/plugin, additive,
    open-closed shape already proven platform-wide (M38 §5)."""

    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class DetectionRuleShape(StrEnum):
    """The three rule shapes behind one `IDetectionEvaluator` interface
    (M37 §5). The shape is fixed at publish time; it never changes for
    a given rule (a shape change is a new rule, not a mutation)."""

    SIGMA = "sigma"
    CORRELATION = "correlation"
    BEHAVIORAL = "behavioral"


class DetectionRole(StrEnum):
    """RBAC scopes for siem_detection's application layer (M37 §16 —
    extends the existing platform RBAC, no parallel model)."""

    VIEWER = "siem_detection:viewer"
    EXECUTOR = "siem_detection:execute"
    ADMIN = "siem_detection:admin"

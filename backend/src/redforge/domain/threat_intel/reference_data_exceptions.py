"""Domain exceptions for the Threat Intelligence Reference Data
sub-context — M22 Phase 1."""

from __future__ import annotations

from redforge.core.exceptions import ValidationError


class InvalidTechniqueIdError(ValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(
            f"Invalid ATT&CK technique id: {raw!r} — expected format 'T####' or 'T####.###'"
        )


class InvalidTacticIdError(ValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid ATT&CK tactic id: {raw!r} — expected format 'TA####'")


class InvalidCveIdError(ValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid CVE id: {raw!r} — expected format 'CVE-YYYY-NNNN'")


class InvalidEpssScoreError(ValidationError):
    pass


class InvalidCvssScoreError(ValidationError):
    pass


class UnknownTacticReferenceError(ValidationError):
    """Raised when an AttackTechnique references a TacticId that has not
    been ingested yet. Techniques must never be linked to a fabricated
    tactic — the referenced tactic must already exist in the catalog."""

    def __init__(self, tactic_id: str) -> None:
        super().__init__(f"Unknown ATT&CK tactic referenced: {tactic_id!r}")


class UnknownTechniqueReferenceError(ValidationError):
    """Raised when an AttackTechnique's parent_technique_id, or an
    AttackTechniqueRelationship's resolved technique side, references a
    technique that has not been ingested yet."""

    def __init__(self, technique_id: str) -> None:
        super().__init__(f"Unknown ATT&CK technique referenced: {technique_id!r}")


class DuplicateIngestionError(ValidationError):
    """Raised when the same (source_system, external_id) global object is
    ingested with content that does not match the previously recorded
    content hash within the same batch — signals a non-idempotent
    resubmission that the caller must investigate rather than silently
    overwrite."""

    def __init__(self, source_system: str, external_id: str) -> None:
        super().__init__(
            f"Duplicate ingestion for {source_system}:{external_id} "
            "with conflicting content in the same batch"
        )


class InvalidIngestionScopeError(ValidationError):
    """Raised when a ReferenceDataIngestionRecord's scope/organization_id
    pairing violates the GLOBAL-must-be-org-less invariant."""

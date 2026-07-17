"""Domain services for the Compliance bounded context."""

from __future__ import annotations

from redforge.domain.compliance.entity import ControlCatalog  # noqa: TC001
from redforge.domain.compliance.exceptions import (
    CatalogIntegrityError,
    InvalidControlStatusTransitionError,
)
from redforge.domain.compliance.value_objects import (
    ControlStatus,
    ControlStatusCode,
    FrameworkKey,
    FrameworkStatus,
)


class CatalogIntegrityValidator:
    """Validates catalog-level invariants before publishing operations.

    A domain service (stateless, no infrastructure dependencies) that
    can be invoked by the application layer before committing a publish.
    """

    def validate_publishable(
        self,
        catalog: ControlCatalog,
        framework_key: FrameworkKey,
    ) -> None:
        """Assert that a framework satisfies all pre-publish invariants.

        Raises CatalogIntegrityError with a descriptive message on the
        first violation found.
        """
        framework = catalog.get_framework(framework_key)

        if framework.status == FrameworkStatus.PUBLISHED:
            raise CatalogIntegrityError(
                f"Framework '{framework_key}' is already published"
            )
        if framework.status == FrameworkStatus.RETIRED:
            raise CatalogIntegrityError(
                f"Framework '{framework_key}' is retired and cannot be re-published"
            )
        if framework.requirement_count() == 0:
            raise CatalogIntegrityError(
                f"Framework '{framework_key}' has no requirements; "
                "publish requires at least one requirement"
            )

        refs: set[str] = set()
        for req in framework.requirements.values():
            if req.requirement_ref in refs:
                raise CatalogIntegrityError(
                    f"Duplicate requirement_ref '{req.requirement_ref}' "
                    f"in framework '{framework_key}'"
                )
            refs.add(req.requirement_ref)

    def validate_catalog_consistency(self, catalog: ControlCatalog) -> list[str]:
        """Return a list of warning strings for non-fatal inconsistencies.

        Used by diagnostic/health endpoints — does not raise.
        """
        warnings: list[str] = []

        for mapping in catalog.list_active_mappings():
            src_fw = catalog.frameworks.get(mapping.source_framework_key)
            tgt_fw = catalog.frameworks.get(mapping.target_framework_key)

            if src_fw is None:
                warnings.append(
                    f"Mapping {mapping.id}: source framework "
                    f"'{mapping.source_framework_key}' not found"
                )
                continue
            if tgt_fw is None:
                warnings.append(
                    f"Mapping {mapping.id}: target framework "
                    f"'{mapping.target_framework_key}' not found"
                )
                continue

            if mapping.source_requirement_id not in src_fw.requirements:
                warnings.append(
                    f"Mapping {mapping.id}: source requirement "
                    f"'{mapping.source_requirement_id}' not found in "
                    f"'{mapping.source_framework_key}'"
                )
            if mapping.target_requirement_id not in tgt_fw.requirements:
                warnings.append(
                    f"Mapping {mapping.id}: target requirement "
                    f"'{mapping.target_requirement_id}' not found in "
                    f"'{mapping.target_framework_key}'"
                )

        return warnings


class ControlStatusEvaluator:
    """Evaluates ControlStatus lifecycle transitions for Phase 2.

    Unknown (future) status values are never rewritten.  Transitions
    involving an unknown current or target status are rejected so
    historical rows remain intact until a future phase defines them.
    """

    _ALLOWED: frozenset[tuple[str, str]] = frozenset(
        {
            (
                ControlStatusCode.NOT_ASSESSED,
                ControlStatusCode.COLLECTING_EVIDENCE,
            ),
            (
                ControlStatusCode.COLLECTING_EVIDENCE,
                ControlStatusCode.PENDING_CONFIRMATION,
            ),
            (
                ControlStatusCode.PENDING_CONFIRMATION,
                ControlStatusCode.TECHNICALLY_VALIDATED,
            ),
        }
    )

    def evaluate_transition(
        self,
        current: ControlStatus,
        target: ControlStatus,
        *,
        evidence_count: int,
    ) -> ControlStatus:
        if current.value == target.value:
            return current

        if not current.is_known:
            raise InvalidControlStatusTransitionError(
                current.value,
                target.value,
                "current status is unknown to this phase and must not be rewritten",
            )
        if not target.is_known:
            raise InvalidControlStatusTransitionError(
                current.value,
                target.value,
                "target status is unknown to this phase",
            )

        pair = (current.value, target.value)
        if pair not in self._ALLOWED:
            raise InvalidControlStatusTransitionError(
                current.value,
                target.value,
                "transition is not in the approved Phase 2 lifecycle",
            )

        if target.value in {
            ControlStatusCode.PENDING_CONFIRMATION,
            ControlStatusCode.TECHNICALLY_VALIDATED,
        } and evidence_count < 1:
            raise InvalidControlStatusTransitionError(
                current.value,
                target.value,
                "at least one ConfirmedEvidenceLink is required",
            )

        return target

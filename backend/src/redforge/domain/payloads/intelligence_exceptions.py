"""Domain exceptions for the Payload Intelligence Engine (PayloadBundle
and the generation pipeline) — kept separate from exceptions.py
(PayloadTemplate's own exceptions) since these are a distinct, additive
concern layered on top."""

from redforge.core.exceptions import ValidationError
from redforge.domain.payloads.exceptions import PayloadError


class EmptyBundleError(ValidationError):
    """Raised when attempting to create a PayloadBundle with zero
    variants — mirrors domain.planning.EmptyPlanError's reasoning: an
    empty bundle is either "nothing was compatible" (the caller's
    problem to handle explicitly) or a pipeline bug, never silently
    accepted."""

    def __init__(self, attack_plan_id: str) -> None:
        super().__init__(
            message=(
                f"Cannot create a PayloadBundle with zero variants for "
                f"attack plan '{attack_plan_id}'"
            ),
            details={"attack_plan_id": attack_plan_id},
        )


class UnresolvedArtifactError(ValidationError):
    """Raised when a PayloadBundle's execution_artifacts reference a
    variant_id not present among its variants — referential integrity,
    the same invariant AttackSequence enforces for depends_on."""

    def __init__(self, variant_id: str) -> None:
        super().__init__(
            message=(
                f"ExecutionArtifacts references variant '{variant_id}' "
                "which is not present in this bundle"
            ),
            details={"variant_id": variant_id},
        )


class BundleAlreadySupersededError(ValidationError):
    """Raised when attempting to supersede an already-superseded bundle."""

    def __init__(self, bundle_id: str) -> None:
        super().__init__(
            message=f"PayloadBundle '{bundle_id}' is already superseded",
            details={"bundle_id": bundle_id},
        )


class NoApplicableTemplateError(PayloadError):
    """Raised when TemplateResolver finds zero templates applicable to
    an attack — distinct from a generic empty-result, since it
    specifically means "the template library has candidates, but none
    matched this attack.\""""

    def __init__(self, attack_id: str) -> None:
        super().__init__(
            message=f"No applicable payload template found for attack '{attack_id}'"
        )
        self.error_code = "NO_APPLICABLE_TEMPLATE"
        self.attack_id = attack_id


class MutationFailedError(PayloadError):
    """Raised when a MutationStrategy cannot be applied to a variant
    (e.g. content becomes empty, or a structural transform fails)."""

    def __init__(self, mutation_type: str, variant_id: str, reason: str) -> None:
        super().__init__(
            message=(
                f"Mutation '{mutation_type}' failed for variant "
                f"'{variant_id}': {reason}"
            )
        )
        self.error_code = "MUTATION_FAILED"
        self.mutation_type = mutation_type
        self.variant_id = variant_id

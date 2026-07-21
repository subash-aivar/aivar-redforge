from __future__ import annotations


class MLPipelineDomainError(Exception):
    pass


class TenantMismatch(MLPipelineDomainError):
    pass


class InvalidModelTransition(MLPipelineDomainError):
    pass


class ArtifactIntegrityError(MLPipelineDomainError):
    pass


class ArtifactNotFoundError(MLPipelineDomainError):
    pass


class InsufficientTrainingData(MLPipelineDomainError):
    pass

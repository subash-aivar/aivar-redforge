"""Domain layer — pure business logic, entities, and domain services.

This layer contains the core business rules of AIVAR RedForge. It depends
only on the core package and has zero dependencies on frameworks, databases,
or HTTP concerns. All code here must be pure Python.

Bounded contexts will be added as subpackages (e.g., domain.validations,
domain.attacks, domain.evidence) as they are developed.
"""

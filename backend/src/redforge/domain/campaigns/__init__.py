"""Enterprise Continuous Validation Campaign bounded context.

A Campaign is a multi-target, policy-driven orchestration of N
ValidationRuns. It sits one architectural layer above ValidationService:
ValidationService executes one target at a time; Campaign coordinates
many executions, tracks collective progress, computes campaign metrics,
and optionally detects drift against a baseline campaign.

Domain layer — imports only redforge.domain.*, redforge.shared.*,
redforge.core.exceptions (ADR-0001).
"""

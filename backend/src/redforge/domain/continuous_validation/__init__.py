"""Continuous Validation Scheduler, Security Drift Detection & Revalidation
Engine bounded context (M14).

Evolves the one-shot validation flow (`domain.validation_execution`) into
a continuous control plane: a tenant-owned `ContinuousValidationPolicy`
declares a target/profile/cadence; a server-controlled scheduler claims
due policies and reuses `ValidationExecutionService.create_and_run()`
(SCHEDULED trigger) for every actual validation run — this bounded
context never executes network validation itself. Comparing the new
run's canonical state against a prior `ValidationStateSnapshot` produces
`SecurityDriftEvent` rows, and drives condition/correlation lifecycle
reconciliation in the existing M8/M9 bounded contexts.
"""

"""Application services for the Security Operations bounded context (M15).

See domain/security_operations/__init__.py for the bounded context's
own scope statement. Every service here READS existing canonical state
(ValidationExecution, SecurityCondition, SecurityCorrelation,
SecurityDriftEvent, ContinuousValidationPolicy, runtime health) — none
of them ever mutate it. The one exception is the runtime-health
transition detector, which writes only to this bounded context's own
two small bookkeeping tables (never to any other bounded context's
tables).
"""

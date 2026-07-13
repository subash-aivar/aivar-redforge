"""Security Operations bounded context — M15.

A READ MODEL over the security truth M1-M14 already produce. Owns
nothing: no assets, no conditions, no correlations, no executions, no
policies, no drift events. It projects those bounded contexts' own
canonical events/state into one tenant-safe, cursor-resumable
operational view.

Backing store: the pre-existing Sprint 24/25 platform event
infrastructure (`domain/platform/events.py` + `PostgreSQLEventStore`),
which was fully built but had zero production writers until this
milestone — see `application/security_operations/README` (module
docstrings) for the reconnaissance finding and reuse decision.
"""

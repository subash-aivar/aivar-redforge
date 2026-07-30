"""Application layer for attack_surface_management (M49B) — commands,
queries, DTOs, ports (repository/UoW/event-publisher contracts), and
orchestrating application services over the M49A domain layer.

Mirrors `risk_engine.application`'s shape exactly: application services
never contain business rules — they only load aggregates via
repository ports, delegate to domain factories/policies/services/
aggregate methods, persist via `async with self._uow: ... save() ...
commit()`, and return read-only DTOs."""

from __future__ import annotations

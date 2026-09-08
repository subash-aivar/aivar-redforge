"""IIocIdentityPort — the read-only ACL contract over IOC identity,
owned by the `ioc_intelligence` bounded context.

`intelligence_relationships` never queries `ioc_intelligence`'s domain
classes, and never duplicates IOC state. This port is the single,
read-only, narrow existence-check seam between the two contexts. A
concrete infrastructure adapter implements it with a plain SQLAlchemy
Core SELECT against that context's own table — never its domain
aggregate types, and never a write path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IIocIdentityPort(ABC):
    @abstractmethod
    async def exists(self, ioc_id: str) -> bool:
        """True iff `ioc_id` identifies a persisted IOC."""
        ...

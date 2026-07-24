"""SIEM shared kernel.

The one package every `siem_*` bounded context is allowed to depend on
(mirroring `redforge.shared`'s existing role, per M37 §1). Contains only
value objects and versioning contracts — no behavior, no infrastructure.
"""

from __future__ import annotations

"""FrameworkDefinitionPort — the adapter protocol for compliance framework data.

Each framework ships as a JSON fixture loaded by a concrete adapter class.
The domain never imports adapters directly; the application service
receives a list of port implementations via constructor injection.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from redforge.domain.compliance.value_objects import FrameworkKey


@runtime_checkable
class FrameworkDefinitionPort(Protocol):
    """Source of truth for a single compliance framework definition.

    Implementors load framework metadata and control requirements from
    a bundled JSON fixture.  They never touch the database — persistence
    is the application service's responsibility.
    """

    @property
    def framework_key(self) -> FrameworkKey:
        """The canonical framework key this adapter serves."""
        ...

    def load_metadata(self) -> dict[str, Any]:
        """Return the framework metadata dict.

        Must include at minimum: name, version, issuing_body, description,
        effective_date.  Optional: tags (list[str]), external_url (str).
        """
        ...

    def load_requirements(self) -> list[dict[str, Any]]:
        """Return a list of control requirement dicts.

        Each dict must include: requirement_ref, title, description,
        domain (ControlDomain value), severity (ControlSeverity value),
        guidance (str), policy_threshold (int 0-100).
        Optional: tags (list[str]), external_ref (str).
        """
        ...

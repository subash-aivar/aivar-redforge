from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_agent_governance.domain.value_objects.enums import AuthorizedActionCategory
    from ai_agent_governance.domain.value_objects.identifiers import AuthorizedActionId


class AuthorizedAction:
    __slots__ = ("action_id", "category", "description")

    def __init__(
        self,
        action_id: AuthorizedActionId,
        category: AuthorizedActionCategory,
        description: str,
    ) -> None:
        self.action_id = action_id
        self.category = category
        self.description = description

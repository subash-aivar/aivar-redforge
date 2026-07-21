from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    def __init__(self, resource: str, resource_id: str) -> None:
        super().__init__(f"{resource} not found: {resource_id}")
        self.resource = resource
        self.resource_id = resource_id


class ApplicationValidationError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    def __init__(self, role_required: str) -> None:
        super().__init__(f"Requires role {role_required}")
        self.role_required = role_required

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationValidationError(ApplicationError):
    pass

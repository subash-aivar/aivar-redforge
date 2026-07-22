from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass

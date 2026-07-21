from __future__ import annotations


class ApplicationForbiddenError(Exception):
    pass


class ApplicationNotFoundError(Exception):
    pass


class ApplicationValidationError(Exception):
    pass


class ApplicationConflictError(Exception):
    pass

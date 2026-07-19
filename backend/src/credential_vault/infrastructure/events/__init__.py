"""Infrastructure event publishers."""

from credential_vault.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)

__all__ = ["StructlogEventPublisher"]

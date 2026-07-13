"""Unit tests for event publisher implementations."""

from redforge.infrastructure.events import InMemoryEventPublisher, NullEventPublisher


class TestInMemoryEventPublisher:
    async def test_publishes_events(self) -> None:
        pub = InMemoryEventPublisher()
        await pub.publish(["event1", "event2"])
        assert len(pub.published) == 2
        assert pub.published[0] == "event1"

    async def test_accumulates(self) -> None:
        pub = InMemoryEventPublisher()
        await pub.publish(["a"])
        await pub.publish(["b"])
        assert len(pub.published) == 2

    async def test_clear(self) -> None:
        pub = InMemoryEventPublisher()
        await pub.publish(["x"])
        pub.clear()
        assert pub.published == []

    def test_conforms_to_protocol(self) -> None:
        from redforge.infrastructure.events import EventPublisher

        assert isinstance(InMemoryEventPublisher(), EventPublisher)
        assert isinstance(NullEventPublisher(), EventPublisher)


class TestNullEventPublisher:
    async def test_discards_silently(self) -> None:
        pub = NullEventPublisher()
        await pub.publish(["event1", "event2"])
        # No error, no storage — just a no-op

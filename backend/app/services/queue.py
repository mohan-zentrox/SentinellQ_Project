"""Streaming/queue abstraction.

Documented production target: Kafka / Redpanda (topics per tenant or per
event-category, consumer groups for the normalizer, rule engine, etc).

Working default for local dev and tests: `InProcessQueueBackend`, a
synchronous in-memory publish/consume implementation with no external
dependencies. A `RedisQueueBackend` adapter is provided as the next step up
(single-process -> multi-process) and only imports `redis` lazily so it
never breaks environments where redis-py isn't installed.

Callers only ever depend on the `QueueBackend` interface, so swapping the
backend later (e.g. to Kafka) requires no changes outside this module.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from typing import Any


class QueueBackend(ABC):
    @abstractmethod
    def publish(self, topic: str, message: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def subscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> None:
        """Register a handler to be invoked (synchronously, for the in-process
        backend) whenever a message is published to `topic`."""
        raise NotImplementedError

    @abstractmethod
    def unsubscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> None:
        raise NotImplementedError


class InProcessQueueBackend(QueueBackend):
    """Synchronous, single-process queue. Messages are delivered immediately
    and in-order to every subscribed handler -- this is what lets
    POST /v1/events/ingest normalize-and-store an event within the same
    request/response cycle for local dev and tests, while still going
    through the same publish/subscribe seam production code will use with
    Kafka.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[dict[str, Any]], None]]] = defaultdict(list)
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        self._history[topic].append(message)
        for handler in self._subscribers[topic]:
            handler(message)

    def subscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> None:
        self._subscribers[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> None:
        if handler in self._subscribers[topic]:
            self._subscribers[topic].remove(handler)

    def history(self, topic: str) -> list[dict[str, Any]]:
        """Test/debug helper: everything ever published to `topic`."""
        return list(self._history[topic])


class RedisQueueBackend(QueueBackend):  # pragma: no cover - not exercised in tests
    """Multi-process working default using Redis lists as a lightweight queue.

    Intentionally NOT the documented production target (Kafka/Redpanda);
    this is the "next step up" adapter for a single-node deployment that
    still needs the API server and worker(s) in separate processes.
    """

    def __init__(self, redis_url: str) -> None:
        import redis  # local import: keep redis an optional dependency

        self._client = redis.Redis.from_url(redis_url)
        self._handlers: dict[str, list[Callable[[dict[str, Any]], None]]] = defaultdict(list)

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        import json

        self._client.rpush(topic, json.dumps(message))
        for handler in self._handlers[topic]:
            handler(message)

    def subscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> None:
        self._handlers[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Callable[[dict[str, Any]], None]) -> None:
        if handler in self._handlers[topic]:
            self._handlers[topic].remove(handler)


_queue_singleton: QueueBackend | None = None


def get_queue() -> QueueBackend:
    global _queue_singleton
    if _queue_singleton is None:
        _queue_singleton = InProcessQueueBackend()
    return _queue_singleton


def reset_queue() -> None:
    """Test helper to get a clean queue between test cases."""
    global _queue_singleton
    _queue_singleton = InProcessQueueBackend()


# Topic names, centralized so producers/consumers never hardcode strings.
TOPIC_RAW_EVENTS = "raw-events"

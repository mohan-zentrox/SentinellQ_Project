"""Streaming/queue abstraction.

Backend is selected by `SENTINELIQ_QUEUE_BACKEND` and resolved in
`get_queue()` -- the setting is actually read, so swapping backends is a
config change, not a code change:

- `in_process` (default): synchronous, single-process. `publish()` delivers
  to subscribed handlers immediately, which is what lets the test suite and
  bare-metal dev run the whole ingestion pipeline inside one request with no
  broker. There is no worker in this mode and none is needed.
- `redis`: a real producer/consumer split. `publish()` only pushes onto a
  Redis list; nothing is processed until `app/worker.py` runs
  `consume_forever()` in a separate process. This is what docker-compose
  uses.
- `kafka`: the documented production target. Not implemented; selecting it
  raises at startup with a pointer rather than silently degrading.

Delivery semantics differ between the two working backends on purpose, and
callers must not assume either: `publish()` is the only guaranteed contract.
`QueueBackend.is_synchronous` tells a caller whether a published message has
already been handled by the time publish returns (see
`app/api/v1/events.py`, which uses it to decide between a `202 queued` and a
`202 processed` response body).
"""
from __future__ import annotations

import json
import logging
import threading
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger(__name__)

Handler = Callable[[dict[str, Any]], None]


class QueueBackend(ABC):
    #: True when publish() has fully processed the message before returning.
    is_synchronous: bool = False

    @abstractmethod
    def publish(self, topic: str, message: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def subscribe(self, topic: str, handler: Handler) -> None:
        """Register a handler for `topic`.

        For the in-process backend this makes the handler run on publish; for
        broker-backed backends it registers the handler with the consumer loop
        (`consume_forever`) and has no effect on producers.
        """
        raise NotImplementedError

    @abstractmethod
    def unsubscribe(self, topic: str, handler: Handler) -> None:
        raise NotImplementedError

    def consume_forever(self, topics: list[str], *, stop: threading.Event | None = None) -> None:
        """Block, dispatching messages to subscribed handlers until `stop` is set.

        No-op for synchronous backends (nothing is ever pending).
        """
        return None


class InProcessQueueBackend(QueueBackend):
    """Synchronous, single-process queue.

    Messages are delivered immediately and in order to every subscribed
    handler, so POST /v1/events/ingest normalizes-and-stores within the same
    request/response cycle -- while still going through the same
    publish/subscribe seam a broker-backed deployment uses.
    """

    is_synchronous = True

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        self._history[topic].append(message)
        # Iterate a copy: a handler is allowed to unsubscribe itself.
        for handler in list(self._subscribers[topic]):
            handler(message)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subscribers[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        if handler in self._subscribers[topic]:
            self._subscribers[topic].remove(handler)

    def history(self, topic: str) -> list[dict[str, Any]]:
        """Test/debug helper: everything ever published to `topic`."""
        return list(self._history[topic])


class RedisQueueBackend(QueueBackend):  # pragma: no cover - requires a Redis server
    """Producer/consumer split over Redis lists.

    Intentionally NOT the documented production target (Kafka/Redpanda); this
    is the "next step up" adapter for a single-node deployment that still
    needs the API and worker in separate processes.

    `publish()` deliberately does *not* invoke local handlers -- doing so
    would double-process every message (once in the API, once in the worker).
    Handlers only fire inside `consume_forever()`.
    """

    is_synchronous = False

    def __init__(self, redis_url: str) -> None:
        import redis  # local import: keep redis an optional dependency

        self._client = redis.Redis.from_url(redis_url)
        self._handlers: dict[str, list[Handler]] = defaultdict(list)

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        self._client.rpush(topic, json.dumps(message, default=str))

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._handlers[topic].append(handler)

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        if handler in self._handlers[topic]:
            self._handlers[topic].remove(handler)

    def consume_forever(self, topics: list[str], *, stop: threading.Event | None = None) -> None:
        settings = get_settings()
        dlq_suffix = settings.queue_dlq_suffix
        while stop is None or not stop.is_set():
            # 1s timeout rather than a blocking-forever BLPOP so `stop` is
            # honoured promptly on SIGTERM.
            popped = self._client.blpop(topics, timeout=1)
            if popped is None:
                continue
            raw_topic, raw_message = popped
            topic = raw_topic.decode() if isinstance(raw_topic, bytes) else raw_topic
            try:
                message = json.loads(raw_message)
            except (TypeError, ValueError):
                logger.exception("queue.undecodable_message", extra={"topic": topic})
                self._client.rpush(f"{topic}{dlq_suffix}", raw_message)
                continue
            for handler in list(self._handlers[topic]):
                try:
                    handler(message)
                except Exception:  # noqa: BLE001 - one bad message must not kill the worker
                    logger.exception("queue.handler_failed", extra={"topic": topic})
                    self._client.rpush(f"{topic}{dlq_suffix}", json.dumps(message, default=str))

    def depth(self, topic: str) -> int:
        return int(self._client.llen(topic))


class KafkaQueueBackend(QueueBackend):  # pragma: no cover - not implemented
    """Documented production target. Not implemented in this repository.

    TODO(C7): implement with confluent-kafka or aiokafka -- topic per
    event-category (or per tenant above a volume threshold), a consumer group
    per downstream stage (normalizer, rule engine), and at-least-once
    semantics with explicit offset commits after the handler succeeds. The
    `QueueBackend` contract above is deliberately narrow enough that no
    caller changes when this lands.
    """

    def __init__(self) -> None:
        raise NotImplementedError(
            "queue_backend='kafka' is the documented production target but is not implemented. "
            "Use 'redis' for a real producer/consumer split, or 'in_process' for single-process dev. "
            "See app/services/queue.py::KafkaQueueBackend."
        )

    def publish(self, topic: str, message: dict[str, Any]) -> None:
        raise NotImplementedError

    def subscribe(self, topic: str, handler: Handler) -> None:
        raise NotImplementedError

    def unsubscribe(self, topic: str, handler: Handler) -> None:
        raise NotImplementedError


_queue_singleton: QueueBackend | None = None


def build_queue(backend: str, *, redis_url: str) -> QueueBackend:
    """Construct a backend by name. Separated from the singleton for testability."""
    if backend == "in_process":
        return InProcessQueueBackend()
    if backend == "redis":
        return RedisQueueBackend(redis_url)
    if backend == "kafka":
        return KafkaQueueBackend()
    raise ValueError(
        f"Unknown SENTINELIQ_QUEUE_BACKEND={backend!r}. Supported: 'in_process', 'redis', 'kafka' (unimplemented)."
    )


def get_queue() -> QueueBackend:
    global _queue_singleton
    if _queue_singleton is None:
        settings = get_settings()
        _queue_singleton = build_queue(settings.queue_backend, redis_url=settings.redis_url)
        logger.info("queue.backend_selected", extra={"backend": settings.queue_backend})
    return _queue_singleton


def reset_queue() -> None:
    """Test helper: drop the singleton so the next get_queue() rebuilds it."""
    global _queue_singleton
    _queue_singleton = None


# Topic names, centralized so producers/consumers never hardcode strings.
TOPIC_RAW_EVENTS = "raw-events"

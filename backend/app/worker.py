"""Ingestion worker: the consumer half of the FM2 streaming seam.

Run with `python -m app.worker` (docker-compose's `worker` service). It
subscribes to the raw-events topic and runs the same pipeline the API runs
inline when the queue is synchronous -- `app/services/pipeline.py` is the
single implementation, so a message produces identical results whichever
process handles it.

This process exists because `SENTINELIQ_QUEUE_BACKEND=redis` makes
`publish()` a pure enqueue: without a worker running, ingested events are
accepted (202) and then never stored. With the default `in_process` backend
there is nothing to consume and the worker exits immediately rather than
idling and pretending to work.

Each message gets its own database session and is committed independently, so
one poison message cannot roll back its neighbours. A handler that raises
sends the message to `<topic>.dlq` (see `RedisQueueBackend.consume_forever`)
instead of taking the worker down.

Usage is NOT metered here: `POST /v1/events/ingest` already billed the batch
when it enqueued. Double-metering would charge every tenant twice.
"""
from __future__ import annotations

import logging
import signal
import sys
import threading
from typing import Any

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal
from app.services.pipeline import process_batch
from app.services.queue import TOPIC_RAW_EVENTS, get_queue

logger = logging.getLogger("app.worker")

_stop = threading.Event()


def _handle_message(message: dict[str, Any]) -> None:
    """Process one raw event in its own transaction.

    Raising propagates to the queue backend, which DLQs the message -- that is
    the intended behaviour for a message we genuinely cannot process, and it
    is why the session is rolled back and closed here rather than reused.
    """
    tenant_id = message.get("tenant_id")
    if not tenant_id:
        raise ValueError("raw-events message is missing tenant_id")

    db = SessionLocal()
    try:
        events, alerts = process_batch(db, tenant_id=tenant_id, messages=[message])
        db.commit()
        logger.info(
            "worker.processed",
            extra={
                "tenant_id": tenant_id,
                "events": len(events),
                "alerts": len(alerts),
            },
        )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _install_signal_handlers() -> None:
    def _request_stop(signum, _frame):  # noqa: ANN001 - signal handler signature
        logger.info("worker.stopping", extra={"signal": signum})
        _stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _request_stop)
        except (ValueError, OSError):  # pragma: no cover - non-main thread / unsupported
            pass


def main() -> int:
    settings = get_settings()
    configure_logging()

    queue = get_queue()
    if queue.is_synchronous:
        logger.warning(
            "worker.not_needed",
            extra={
                "backend": settings.queue_backend,
                "detail": (
                    "queue_backend is synchronous: the API processes events inline and there is nothing "
                    "to consume. Set SENTINELIQ_QUEUE_BACKEND=redis to run a real producer/consumer split."
                ),
            },
        )
        return 0

    _install_signal_handlers()
    queue.subscribe(TOPIC_RAW_EVENTS, _handle_message)
    logger.info("worker.started", extra={"backend": settings.queue_backend, "topic": TOPIC_RAW_EVENTS})
    try:
        queue.consume_forever([TOPIC_RAW_EVENTS], stop=_stop)
    finally:
        queue.unsubscribe(TOPIC_RAW_EVENTS, _handle_message)
        logger.info("worker.stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

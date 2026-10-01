"""Structured logging.

`app/tenancy/middleware.py` has always stamped `request.state.tenant_id` "for
structured logging" -- this module is the structured logging that claim
referred to. Without it the stamp went nowhere.

Two formats, chosen by `SENTINELIQ_LOG_FORMAT`:
- `text` (default): human-readable, for local dev.
- `json`: one JSON object per line, for log aggregation. docker-compose sets
  this.

Call sites log an event name plus an `extra` dict (`logger.info("worker.
processed", extra={"tenant_id": ...})`) rather than interpolating into the
message. The JSON formatter promotes those extras to top-level fields, so
`tenant_id` is queryable instead of buried in a string.
"""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings

#: Set by TenantContextMiddleware for the duration of a request so every log
#: line emitted while handling it carries the tenant and request id without
#: each call site having to pass them.
request_context: ContextVar[dict[str, Any]] = ContextVar("request_context", default={})

#: LogRecord attributes that are not caller-supplied extras.
_STANDARD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
) | {"message", "asctime", "taskName"}


class SafeLogger(logging.Logger):
    """Logger whose `extra` dict cannot crash the caller.

    stdlib `Logger.makeRecord` raises KeyError if `extra` contains a key that
    collides with a LogRecord attribute -- `created`, `module`, `name`,
    `message`, `filename`, `args`, `process`... Several of those are natural
    names for application data ("created": 12 indicators created), so the
    collision is easy to hit and the failure mode is terrible: a log line taking
    down the request it was describing, only on the success path, only in
    production.

    Colliding keys are renamed with a `x_` prefix rather than dropped, so the
    value still reaches the log instead of vanishing silently.
    """

    def makeRecord(self, name, level, fn, lno, msg, args, exc_info, func=None, extra=None, sinfo=None):  # noqa: A002
        if extra:
            safe = {
                (f"x_{key}" if key in _RESERVED_RECORD_KEYS else key): value
                for key, value in extra.items()
            }
        else:
            safe = extra
        return super().makeRecord(name, level, fn, lno, msg, args, exc_info, func, safe, sinfo)


#: Keys stdlib logging refuses in `extra`. Mirrors the check in Logger.makeRecord.
_RESERVED_RECORD_KEYS = _STANDARD_ATTRS | {"message", "asctime"}


class ContextFilter(logging.Filter):
    """Merge the current request context onto every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in request_context.get().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_ATTRS or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # default=str so a stray datetime/UUID in an extra never turns a log
        # line into a crash inside the logging machinery.
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _STANDARD_ATTRS and not k.startswith("_")
        }
        return f"{base} {extras}" if extras else base


_configured = False


def configure_logging(force: bool = False) -> None:
    """Install handlers on the root logger. Idempotent."""
    global _configured
    if _configured and not force:
        return

    settings = get_settings()

    # Install SafeLogger before any further getLogger() calls so application
    # loggers are collision-proof. Loggers created earlier keep the stdlib class;
    # re-point them explicitly rather than leaving a mixed fleet.
    logging.setLoggerClass(SafeLogger)
    for existing in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(existing, logging.Logger) and not isinstance(existing, SafeLogger):
            existing.__class__ = SafeLogger

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(ContextFilter())
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level.upper())

    # uvicorn installs its own handlers; route them through ours so request
    # logs and application logs share one format.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True

    _configured = True

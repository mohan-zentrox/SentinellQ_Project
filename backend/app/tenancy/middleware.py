"""Tenant context middleware.

This is a *defense-in-depth / observability* layer, not the primary
enforcement mechanism: primary tenant enforcement happens in
app/core/deps.py (get_current_user / get_tenant_from_service_token), whose
resolved tenant_id is what every service-layer query actually filters on --
that's what backend/tests/test_tenant_isolation.py exercises.

This middleware best-effort-decodes the caller's tenant from the
Authorization header (without raising on failure -- auth is still enforced
downstream by the route dependencies), stamps it onto
`request.state.tenant_id`, and binds it into the logging context
(`app/core/logging.py`) so every log line emitted while handling the request
carries `tenant_id` and `request_id` as queryable fields.

It also records request latency and status into the metrics registry
(`app/core/metrics.py`), which is what `GET /metrics` serves.
"""
from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import request_context
from app.core.metrics import metrics
from app.core.security import decode_access_token

logger = logging.getLogger("sentineliq.tenancy")


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        tenant_id: str | None = None
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]
            try:
                payload = decode_access_token(token)
                tenant_id = payload.get("tenantId")
            except Exception:  # noqa: BLE001 - best effort only, never blocks the request
                tenant_id = None
        elif request.headers.get("x-service-token"):
            tenant_id = "service-token-auth"  # resolved to a real tenant_id downstream

        # Honour an upstream request id when there is one so a trace survives
        # the hop from a load balancer or the nginx proxy.
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.tenant_id = tenant_id
        request.state.request_id = request_id

        token_ctx = request_context.set(
            {
                "request_id": request_id,
                "tenant_id": tenant_id,
                "path": request.url.path,
                "method": request.method,
            }
        )
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            metrics.increment("http_requests_total", {"method": request.method, "status": "500"})
            logger.exception("request.unhandled_error")
            raise
        finally:
            request_context.reset(token_ctx)

        elapsed_ms = (time.perf_counter() - started) * 1000
        metrics.increment("http_requests_total", {"method": request.method, "status": str(response.status_code)})
        metrics.observe("http_request_duration_ms", elapsed_ms, {"method": request.method})

        response.headers["X-Request-Id"] = request_id
        if tenant_id:
            response.headers["X-Tenant-Context"] = tenant_id
        return response

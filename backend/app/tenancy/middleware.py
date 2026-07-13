"""Tenant context middleware.

This is a *defense-in-depth / observability* layer, not the primary
enforcement mechanism: primary tenant enforcement happens in
app/core/deps.py (get_current_user / get_tenant_from_service_token), whose
resolved tenant_id is what every service-layer query actually filters on --
that's what backend/tests/test_tenant_isolation.py exercises.

This middleware additionally best-effort-decodes the caller's tenant from
the Authorization header (without raising on failure -- auth is still
enforced downstream by the route dependencies) and stamps it onto
`request.state.tenant_id` purely so structured logs/metrics/future
rate-limiting can be tenant-aware.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

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

        request.state.tenant_id = tenant_id
        logger.debug("request tenant_context tenant_id=%s path=%s", tenant_id, request.url.path)
        response = await call_next(request)
        if tenant_id:
            response.headers["X-Tenant-Context"] = tenant_id
        return response

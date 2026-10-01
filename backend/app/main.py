"""SentinelIQ backend entrypoint.

AI-Driven Unified Security Operations & Threat Analytics SaaS Platform.
This is AUTHORIZED defensive/internal SecOps tooling: ingestion,
normalization, rule-based and ML detection, threat-intel enrichment, case
management, playbook automation, analytics, and compliance reporting for an
organization's own security telemetry. It is explicitly NOT an offensive
security tool.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api.v1 import (
    admin,
    alerts,
    analytics,
    auth,
    billing,
    cases,
    events,
    playbooks,
    reports,
    rules,
    tenants,
    threat_intel,
)
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.metrics import metrics
from app.db.base import Base
from app.db.seed import seed_default_plans
from app.db.session import SessionLocal, engine
from app.services.rule_engine import ConditionError
from app.tenancy.middleware import TenantContextMiddleware

settings = get_settings()
configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Local dev / test convenience only, and opt-out-able. Container deploys
    # set SENTINELIQ_AUTO_CREATE_SCHEMA=false and run `alembic upgrade head`
    # from docker-entrypoint.sh, so schema is always versioned in any
    # environment that outlives a single process.
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_plans(db)
    finally:
        db.close()
    logger.info(
        "app.started",
        extra={
            "environment": settings.environment,
            "queue_backend": settings.queue_backend,
            "telemetry_store": settings.telemetry_store_backend,
            "billing_provider": settings.billing_provider,
            "auth_provider": settings.auth_provider,
        },
    )
    yield


app = FastAPI(
    title="SentinelIQ API",
    description="AI-Driven Unified Security Operations & Threat Analytics SaaS Platform (defensive/internal SecOps).",
    version="0.2.0",
    openapi_version="3.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TenantContextMiddleware)


@app.exception_handler(ConditionError)
async def _condition_error_handler(request: Request, exc: ConditionError) -> JSONResponse:
    """A malformed rule condition is a client error (422), not a 500.

    Routes validate up front, but an evaluation reached through another path
    (e.g. a rule stored before a validation rule tightened) can still raise,
    and a stack trace is the wrong answer to "your condition is invalid".
    """
    return JSONResponse(status_code=422, content={"detail": f"Invalid rule condition: {exc}"})


api_prefix = settings.api_prefix
app.include_router(auth.router, prefix=api_prefix)
app.include_router(tenants.router, prefix=api_prefix)
app.include_router(events.router, prefix=api_prefix)
app.include_router(rules.router, prefix=api_prefix)
app.include_router(alerts.router, prefix=api_prefix)
app.include_router(cases.router, prefix=api_prefix)
app.include_router(billing.router, prefix=api_prefix)
app.include_router(analytics.router, prefix=api_prefix)
app.include_router(threat_intel.router, prefix=api_prefix)
app.include_router(playbooks.router, prefix=api_prefix)
app.include_router(reports.router, prefix=api_prefix)
app.include_router(admin.router, prefix=api_prefix)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentineliq-api"}


@app.get("/readiness", tags=["meta"])
def readiness() -> JSONResponse:
    """Readiness, as distinct from liveness.

    /health answers "is this process up" (what the container healthcheck
    polls). This answers "can it serve traffic", which requires the metadata
    database to be reachable -- a pod that is up but cannot reach Postgres
    should be pulled from the load balancer, not restarted.
    """
    from sqlalchemy import text

    checks: dict[str, str] = {}
    status_code = 200
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 - the point is to report, not raise
        checks["database"] = f"error: {type(exc).__name__}"
        status_code = 503
    finally:
        db.close()

    return JSONResponse(
        status_code=status_code,
        content={"status": "ok" if status_code == 200 else "degraded", "checks": checks},
    )


@app.get("/metrics", tags=["meta"], response_class=PlainTextResponse)
def prometheus_metrics() -> PlainTextResponse:
    """Prometheus text-format metrics (see app/core/metrics.py).

    Unauthenticated by design, like a conventional Prometheus endpoint: it
    exposes aggregate request counts and latencies with no tenant labels and no
    telemetry contents. Restrict it at the ingress if the deployment's network
    is not already closed, or set SENTINELIQ_METRICS_ENABLED=false.
    """
    if not settings.metrics_enabled:
        return PlainTextResponse("metrics disabled\n", status_code=404)
    return PlainTextResponse(metrics.render())

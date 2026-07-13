"""SentinelIQ backend entrypoint.

AI-Driven Unified Security Operations & Threat Analytics SaaS Platform.
This is AUTHORIZED defensive/internal SecOps tooling: ingestion,
normalization, rule-based detection, case management, and analytics for an
organization's own security telemetry. It is explicitly NOT an offensive
security tool.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import alerts, analytics, auth, billing, cases, events, rules, tenants
from app.core.config import get_settings
from app.db.base import Base
from app.db.seed import seed_default_plans
from app.db.session import SessionLocal, engine
from app.tenancy.middleware import TenantContextMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Local dev / test convenience: create tables if they don't exist yet.
    # Production deployments manage schema via Alembic migrations
    # (see backend/alembic.ini, backend/app/alembic/) rather than relying on
    # this call, which is a no-op once migrations have run.
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_plans(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="SentinelIQ API",
    description="AI-Driven Unified Security Operations & Threat Analytics SaaS Platform (defensive/internal SecOps).",
    version="0.1.0",
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

api_prefix = settings.api_prefix
app.include_router(auth.router, prefix=api_prefix)
app.include_router(tenants.router, prefix=api_prefix)
app.include_router(events.router, prefix=api_prefix)
app.include_router(rules.router, prefix=api_prefix)
app.include_router(alerts.router, prefix=api_prefix)
app.include_router(cases.router, prefix=api_prefix)
app.include_router(billing.router, prefix=api_prefix)
app.include_router(analytics.router, prefix=api_prefix)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentineliq-api"}

"""Pytest fixtures.

The whole suite runs against an isolated in-memory SQLite database per test
function (via StaticPool so the single in-memory connection is shared across
the app's dependency-injected sessions) and the in-process queue backend --
zero external services required, matching the "working default" adapters
described in docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import os

import email_validator

# Tests use addresses on the `.test` TLD (RFC 2606 reserved for exactly this
# purpose). email-validator treats `.test` as a special-use domain and
# rejects it by default; it exposes this exact flag to opt back in for
# automated test suites. Must be set before `app.*` is imported (pydantic's
# EmailStr resolves email-validator's behaviour at import/validation time).
email_validator.TEST_ENVIRONMENT = True

# Must be set before `app.*` is imported anywhere: app/db/session.py binds a
# module-level engine at import time. Pointing the *default* engine at a
# throwaway in-memory SQLite database (rather than a `./sentineliq.db` file)
# keeps `app.main`'s startup lifespan hook (which runs against that default
# engine, independent of the per-test dependency override below) from
# littering the working directory when the test suite runs.
os.environ.setdefault("SENTINELIQ_DATABASE_URL", "sqlite://")

from collections.abc import Generator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.seed import seed_default_plans  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services.queue import reset_queue  # noqa: E402


@pytest.fixture()
def db_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def db_sessionmaker(db_engine) -> sessionmaker:
    return sessionmaker(bind=db_engine, autoflush=False, autocommit=False, future=True)


@pytest.fixture()
def db_session(db_sessionmaker) -> Generator[Session, None, None]:
    session = db_sessionmaker()
    try:
        seed_default_plans(session)
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_sessionmaker, db_session) -> Generator[TestClient, None, None]:
    def _override_get_db() -> Generator[Session, None, None]:
        session = db_sessionmaker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    reset_queue()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# --------------------------------------------------------------------------
# Small helpers shared across test modules.
# --------------------------------------------------------------------------
def signup(client: TestClient, *, company: str, email: str, password: str = "correct-horse-1") -> dict:
    resp = client.post(
        "/v1/auth/signup",
        json={"companyName": company, "email": email, "password": password, "fullName": "Owner One"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def create_service_token(client: TestClient, *, owner_token: str, name: str = "ingest-token") -> str:
    resp = client.post(
        "/v1/tenants/me/service-tokens",
        json={"name": name},
        headers=auth_headers(owner_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["token"]

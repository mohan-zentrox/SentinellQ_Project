"""Central application configuration.

All values are overridable via environment variables (see ../../.env.example
at the repo root). Defaults are chosen so the app runs fully locally with
zero external services (SQLite + in-process queue + mocked Stripe) which is
what backend/tests relies on.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SENTINELIQ_", extra="ignore")

    app_name: str = "SentinelIQ"
    environment: str = "local"
    api_prefix: str = "/v1"

    # --- Metadata DB (PostgreSQL in prod, SQLite for local dev / tests) ---
    database_url: str = "sqlite:///./sentineliq.db"

    # --- Auth ---
    jwt_secret: str = "change-me-in-production-this-is-a-dev-only-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 12

    # --- Telemetry store adapter (documented target: ClickHouse/OpenSearch) ---
    telemetry_store_backend: str = "postgres"  # postgres | (future) clickhouse | opensearch

    # --- Streaming / queue adapter (documented target: Kafka/Redpanda) ---
    queue_backend: str = "in_process"  # in_process | redis | (future) kafka

    redis_url: str = "redis://localhost:6379/0"

    # --- Billing (documented target: real Stripe) ---
    billing_provider: str = "mock_stripe"  # mock_stripe | (future) stripe
    stripe_api_key: str = "sk_test_placeholder"
    default_plan_slug: str = "free"

    # --- CORS ---
    cors_origins: list[str] = ["http://localhost:5173"]


@lru_cache
def get_settings() -> Settings:
    return Settings()

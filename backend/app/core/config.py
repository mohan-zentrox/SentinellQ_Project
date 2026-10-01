"""Central application configuration.

All values are overridable via environment variables (see ../../.env.example
at the repo root). Defaults are chosen so the app runs fully locally with
zero external services (SQLite + in-process queue + mocked Stripe) which is
what backend/tests relies on.

Every `*_backend` / `*_provider` setting below is actually read by the
corresponding factory function -- `get_queue()`, `get_telemetry_store()`,
`get_billing_provider()`, `get_threat_intel_provider()`,
`get_notification_channels()`, `get_auth_provider()`. Changing a backend is a
config change, not a code change.
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

    # Bootstrap the schema with Base.metadata.create_all() on startup. True is
    # right for SQLite dev/test; container deploys set this False and let
    # docker-entrypoint.sh run `alembic upgrade head` instead.
    auto_create_schema: bool = True

    # --- Auth ---
    jwt_secret: str = "change-me-in-production-this-is-a-dev-only-secret"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 12
    refresh_token_expire_days: int = 30
    # Failed logins per email+IP before a 429, and the window they're counted in.
    login_rate_limit_attempts: int = 10
    login_rate_limit_window_seconds: int = 300
    # Auth provider: local (email+password) | oidc (per-tenant SSO config).
    auth_provider: str = "local"

    # --- Telemetry store adapter (documented target: ClickHouse/OpenSearch) ---
    telemetry_store_backend: str = "postgres"  # postgres | clickhouse | opensearch

    # --- Streaming / queue adapter (documented target: Kafka/Redpanda) ---
    queue_backend: str = "in_process"  # in_process | redis | kafka
    redis_url: str = "redis://localhost:6379/0"
    # Messages that fail decoding or whose handler raises are pushed to
    # "<topic><suffix>" rather than dropped.
    queue_dlq_suffix: str = ".dlq"

    # --- Detection (FM4) ---
    # Evaluate enabled rules against each batch as it is ingested, instead of
    # only when an analyst POSTs /detection-rules/run-all.
    detection_on_ingest: bool = True
    # Default lookback for a whole-corpus rule run when the rule itself
    # doesn't specify one. Bounds the scan so a run-all can't degrade into a
    # full table scan as a tenant's event volume grows.
    detection_default_window_minutes: int = 60 * 24 * 7
    # Hard cap on events pulled into memory by a single rule evaluation.
    detection_max_scan_events: int = 50_000

    # --- Threat intelligence (FM5) ---
    threat_intel_provider: str = "local"  # local (DB-backed) | http_feed
    threat_intel_feed_url: str | None = None
    threat_intel_feed_api_key: str | None = None
    threat_intel_enrich_on_ingest: bool = True
    threat_intel_default_ttl_hours: int = 24 * 7

    # --- ML detection (C8) ---
    ml_detection_enabled: bool = False
    ml_model_dir: str = "./var/models"
    ml_score_alert_threshold: float = 0.85
    ml_training_min_events: int = 200

    # --- SOAR (FM7) ---
    soar_enabled: bool = True
    # Actions flagged high-risk always require an explicit human approval.
    soar_require_approval_for_high_risk: bool = True
    soar_webhook_timeout_seconds: float = 5.0
    soar_max_actions_per_run: int = 25

    # --- Notifications (FM6 alerting) ---
    notification_channels: list[str] = ["log"]  # log | webhook | email
    notification_webhook_url: str | None = None
    notification_webhook_timeout_seconds: float = 5.0
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_address: str = "alerts@sentineliq.local"
    smtp_use_tls: bool = True
    # Minimum alert severity that triggers a notification.
    notification_min_severity: str = "high"

    # --- Compliance reporting (FM9) ---
    report_dir: str = "./var/reports"
    # Download URLs are HMAC-signed with this secret; defaults to jwt_secret
    # when unset so there is no silently-unsigned mode.
    report_signing_secret: str | None = None
    report_url_ttl_seconds: int = 3600

    # --- Billing (documented target: real Stripe) ---
    billing_provider: str = "mock_stripe"  # mock_stripe | stripe
    stripe_api_key: str = "sk_test_placeholder"
    stripe_webhook_secret: str | None = None
    default_plan_slug: str = "free"

    # --- Observability ---
    log_level: str = "INFO"
    log_format: str = "text"  # text | json
    metrics_enabled: bool = True

    # --- CORS ---
    cors_origins: list[str] = ["http://localhost:5173"]

    @property
    def effective_report_signing_secret(self) -> str:
        return self.report_signing_secret or self.jwt_secret


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test helper: drop the cached Settings so env changes take effect."""
    get_settings.cache_clear()

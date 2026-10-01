from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse


class AuditLogOut(CamelModel):
    id: str
    tenant_id: str
    actor_user_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    detail: dict[str, Any]
    ip_address: str | None
    created_at: datetime


class AuditLogListResponse(PaginatedResponse):
    items: list[AuditLogOut]


class NotificationDeliveryOut(CamelModel):
    id: str
    tenant_id: str
    alert_id: str | None
    case_id: str | None
    channel: str
    status: str
    target: str | None
    detail: dict[str, Any]
    error: str | None
    duration_ms: int | None
    created_at: datetime


class NotificationDeliveryListResponse(PaginatedResponse):
    items: list[NotificationDeliveryOut]


class MLModelOut(CamelModel):
    id: str
    tenant_id: str
    version: str
    algorithm: str
    feature_names: list[str]
    trained_at: datetime
    training_event_count: int
    training_window_start: datetime | None
    training_window_end: datetime | None
    is_active: bool
    score_threshold: float
    scored_event_count: int
    alert_count: int
    metrics: dict[str, Any]
    created_at: datetime
    # `parameters` is deliberately omitted: the learned frequency tables can be
    # megabytes, and they are also an exact description of the tenant's
    # behavioural baseline -- not something to ship in a routine list response.


class MLModelUpdate(CamelModel):
    is_active: bool | None = None
    score_threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class TrainModelRequest(CamelModel):
    window_days: int = Field(default=30, ge=1, le=366)
    activate: bool = True


class TrainModelResponse(CamelModel):
    trained: bool
    model: MLModelOut | None = None
    detail: str | None = None


class SsoConfigUpsert(CamelModel):
    protocol: str = Field(default="oidc", pattern="^(oidc|saml)$")
    issuer: str = Field(min_length=1, max_length=500)
    client_id: str = Field(min_length=1, max_length=255)
    #: Name of the env var / mounted secret holding the client secret. The
    #: secret itself is never accepted or stored here.
    client_secret_env_var: str | None = Field(default=None, max_length=100)
    authorization_endpoint: str | None = Field(default=None, max_length=500)
    token_endpoint: str | None = Field(default=None, max_length=500)
    jwks_uri: str | None = Field(default=None, max_length=500)
    saml_metadata_url: str | None = Field(default=None, max_length=500)
    role_mapping: dict[str, str] = Field(default_factory=dict)
    default_role: str = Field(default="viewer", pattern="^(owner|admin|analyst|viewer)$")
    jit_provisioning: bool = True
    is_enabled: bool = False
    sso_required: bool = False


class SsoConfigOut(CamelModel):
    id: str
    tenant_id: str
    protocol: str
    issuer: str
    client_id: str
    client_secret_env_var: str | None
    authorization_endpoint: str | None
    token_endpoint: str | None
    jwks_uri: str | None
    saml_metadata_url: str | None
    role_mapping: dict[str, str]
    default_role: str
    jit_provisioning: bool
    is_enabled: bool
    sso_required: bool
    verified_at: datetime | None
    created_at: datetime


class SettingsOverview(CamelModel):
    """Non-secret view of which adapters this deployment resolved."""

    environment: str
    queue_backend: str
    telemetry_store_backend: str
    billing_provider: str
    auth_provider: str
    detection_on_ingest: bool
    ml_detection_enabled: bool
    threat_intel_enrich_on_ingest: bool
    soar_enabled: bool
    soar_require_approval_for_high_risk: bool
    notification_channels: list[str]
    notification_min_severity: str
    notification_webhook_configured: bool
    smtp_configured: bool
    auto_create_schema: bool
    metrics_enabled: bool

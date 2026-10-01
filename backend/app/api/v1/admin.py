"""FM11: Platform administration.

`docs/ARCHITECTURE.md` listed FM11 as "covered minimally by FM1; dedicated
admin surface is future work". This is that surface, scoped to what a tenant
admin genuinely needs and cannot get elsewhere:

- the audit log (who changed what),
- ML model lifecycle (train, list, activate, threshold) for C8,
- per-tenant SSO configuration for the FM1 extension,
- a settings view showing which adapters this deployment actually resolved.

Everything here is tenant-scoped and admin+ gated. There is deliberately no
cross-tenant "platform operator" surface: that would need a separate identity
domain and its own authorization model, and bolting it onto tenant-scoped JWTs
is how multi-tenant systems grow a privilege-escalation path.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import client_ip, require_role
from app.db.session import get_db
from app.models.audit import AuditLogEntry
from app.models.ml import MLModelVersion
from app.models.notification import NotificationDelivery
from app.models.sso import TenantSsoConfig
from app.models.user import Role, User
from app.schemas.admin import (
    AuditLogListResponse,
    AuditLogOut,
    MLModelOut,
    MLModelUpdate,
    NotificationDeliveryListResponse,
    NotificationDeliveryOut,
    SettingsOverview,
    SsoConfigOut,
    SsoConfigUpsert,
    TrainModelRequest,
    TrainModelResponse,
)
from app.services.audit import record_audit
from app.services.ml_detection import activate_model, get_active_model, train_model

router = APIRouter(prefix="/admin", tags=["admin"])


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------
@router.get("/audit-log", response_model=AuditLogListResponse)
def list_audit_log(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None, max_length=100),
    actor_user_id: str | None = Query(default=None, alias="actorUserId"),
    days: int = Query(default=90, ge=1, le=366),
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> AuditLogListResponse:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    query = db.query(AuditLogEntry).filter(
        AuditLogEntry.tenant_id == current_user.tenant_id,
        AuditLogEntry.created_at >= since,
    )
    if action:
        # Prefix match so "user." returns every user-related action.
        query = query.filter(AuditLogEntry.action.like(f"{action}%"))
    if actor_user_id:
        query = query.filter(AuditLogEntry.actor_user_id == actor_user_id)

    total = query.count()
    rows = (
        query.order_by(AuditLogEntry.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AuditLogListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[AuditLogOut.model_validate(row) for row in rows],
    )


# --------------------------------------------------------------------------
# Notification deliveries
# --------------------------------------------------------------------------
@router.get("/notifications", response_model=NotificationDeliveryListResponse)
def list_notification_deliveries(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    delivery_status: str | None = Query(default=None, alias="status", pattern="^(sent|failed|suppressed)$"),
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> NotificationDeliveryListResponse:
    """Was the on-call actually told? This is the record that answers it."""
    query = db.query(NotificationDelivery).filter(NotificationDelivery.tenant_id == current_user.tenant_id)
    if delivery_status:
        query = query.filter(NotificationDelivery.status == delivery_status)
    total = query.count()
    rows = (
        query.order_by(NotificationDelivery.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return NotificationDeliveryListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[NotificationDeliveryOut.model_validate(row) for row in rows],
    )


# --------------------------------------------------------------------------
# ML models (C8)
# --------------------------------------------------------------------------
@router.get("/ml-models", response_model=list[MLModelOut])
def list_ml_models(
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> list[MLModelVersion]:
    return (
        db.query(MLModelVersion)
        .filter(MLModelVersion.tenant_id == current_user.tenant_id)
        .order_by(MLModelVersion.trained_at.desc())
        .all()
    )


@router.post("/ml-models/train", response_model=TrainModelResponse)
def train_ml_model(
    payload: TrainModelRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> TrainModelResponse:
    """Fit a new baseline on this tenant's recent telemetry.

    Returns `trained: false` with a reason -- not an error -- when the tenant has
    too little history. A model fitted on a handful of events would flag almost
    everything, so refusing is the correct outcome, and it is an expected state
    for a new tenant rather than a failure.
    """
    model = train_model(
        db,
        tenant_id=current_user.tenant_id,
        window_days=payload.window_days,
        activate=payload.activate,
    )
    if model is None:
        db.commit()
        settings = get_settings()
        return TrainModelResponse(
            trained=False,
            detail=(
                f"Not enough telemetry to fit a baseline: at least "
                f"{settings.ml_training_min_events} events are required in the training window."
            ),
        )

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="ml_model.trained",
        target_type="ml_model",
        target_id=model.id,
        detail={
            "version": model.version,
            "events": model.training_event_count,
            "activated": payload.activate,
        },
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(model)
    return TrainModelResponse(trained=True, model=MLModelOut.model_validate(model))


@router.patch("/ml-models/{model_id}", response_model=MLModelOut)
def update_ml_model(
    model_id: str,
    payload: MLModelUpdate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> MLModelVersion:
    """Activate a model version or adjust its alert threshold.

    Activation is how a bad model is rolled back: the previous version is still
    there, and pointing scoring back at it is one call. Raising the threshold is
    the quieter remedy when a model is right but too noisy.
    """
    model = db.get(MLModelVersion, model_id)
    if model is None or model.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Model version not found")

    changes = payload.model_dump(exclude_unset=True)
    if changes.get("score_threshold") is not None:
        model.score_threshold = changes["score_threshold"]
    if changes.get("is_active") is True:
        activate_model(db, tenant_id=current_user.tenant_id, model=model)
    elif changes.get("is_active") is False:
        # Deactivating the only active model disables ML scoring for the tenant,
        # which is a legitimate kill switch.
        model.is_active = False

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="ml_model.updated",
        target_type="ml_model",
        target_id=model.id,
        detail={"fields": sorted(changes), "version": model.version},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(model)
    return model


@router.get("/ml-models/active", response_model=MLModelOut | None)
def get_active_ml_model(
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> MLModelVersion | None:
    return get_active_model(db, tenant_id=current_user.tenant_id)


# --------------------------------------------------------------------------
# SSO configuration (FM1 extension)
# --------------------------------------------------------------------------
@router.get("/sso", response_model=SsoConfigOut | None)
def get_sso_config(
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> TenantSsoConfig | None:
    return db.execute(
        select(TenantSsoConfig).where(TenantSsoConfig.tenant_id == current_user.tenant_id)
    ).scalar_one_or_none()


@router.put("/sso", response_model=SsoConfigOut)
def upsert_sso_config(
    payload: SsoConfigUpsert,
    request: Request,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> TenantSsoConfig:
    """Create or replace the tenant's SSO configuration. Owner-only.

    Two guards that exist to stop a tenant locking itself out:

    - `ssoRequired` cannot be set while `isEnabled` is false. Mandating an IdP
      that is switched off would disable password login with nothing to replace
      it, locking every user out with no in-product recovery.
    - `ssoRequired` cannot be set before the config has been verified. An issuer
      typo would do the same thing more subtly.
    """
    from app.services.sso import validate_sso_config

    if payload.sso_required and not payload.is_enabled:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "ssoRequired cannot be set while isEnabled is false: that would disable password login "
            "with no working alternative.",
        )

    config = db.execute(
        select(TenantSsoConfig).where(TenantSsoConfig.tenant_id == current_user.tenant_id)
    ).scalar_one_or_none()

    if payload.sso_required and (config is None or config.verified_at is None):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Verify the SSO configuration (POST /v1/admin/sso/verify) before making it required.",
        )

    try:
        validate_sso_config(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if config is None:
        config = TenantSsoConfig(tenant_id=current_user.tenant_id)
        db.add(config)

    for field, value in payload.model_dump().items():
        setattr(config, field, value)
    db.flush()

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="sso_config.upserted",
        target_type="sso_config",
        target_id=config.id,
        detail={
            "protocol": config.protocol,
            "issuer": config.issuer,
            "is_enabled": config.is_enabled,
            "sso_required": config.sso_required,
        },
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(config)
    return config


@router.post("/sso/verify", response_model=SsoConfigOut)
def verify_sso_config(
    request: Request,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> TenantSsoConfig:
    """Check the configured issuer's OIDC discovery document and record success.

    Verification is a precondition for `ssoRequired` precisely so that the
    lockout path requires a working IdP, not just a saved form.
    """
    from app.services.sso import SsoError, verify_discovery

    config = db.execute(
        select(TenantSsoConfig).where(TenantSsoConfig.tenant_id == current_user.tenant_id)
    ).scalar_one_or_none()
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No SSO configuration for this tenant")

    try:
        discovered = verify_discovery(config)
    except SsoError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"SSO verification failed: {exc}") from exc

    config.authorization_endpoint = discovered.get("authorization_endpoint") or config.authorization_endpoint
    config.token_endpoint = discovered.get("token_endpoint") or config.token_endpoint
    config.jwks_uri = discovered.get("jwks_uri") or config.jwks_uri
    config.verified_at = datetime.now(timezone.utc)

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="sso_config.verified",
        target_type="sso_config",
        target_id=config.id,
        detail={"issuer": config.issuer},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(config)
    return config


@router.delete("/sso", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_sso_config(
    request: Request,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    config = db.execute(
        select(TenantSsoConfig).where(TenantSsoConfig.tenant_id == current_user.tenant_id)
    ).scalar_one_or_none()
    if config is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No SSO configuration for this tenant")
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="sso_config.deleted",
        target_type="sso_config",
        target_id=config.id,
        ip_address=client_ip(request),
    )
    db.delete(config)
    db.commit()


# --------------------------------------------------------------------------
# Deployment settings overview
# --------------------------------------------------------------------------
@router.get("/settings", response_model=SettingsOverview)
def get_settings_overview(
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
) -> SettingsOverview:
    """Which adapters this deployment actually resolved.

    Returns only non-secret selectors and booleans -- never a URL containing
    credentials, never an API key, never the JWT secret. The point is to answer
    "is detection-on-ingest actually on in this environment?" without an
    operator having to read the container's env.
    """
    settings = get_settings()
    return SettingsOverview(
        environment=settings.environment,
        queue_backend=settings.queue_backend,
        telemetry_store_backend=settings.telemetry_store_backend,
        billing_provider=settings.billing_provider,
        auth_provider=settings.auth_provider,
        detection_on_ingest=settings.detection_on_ingest,
        ml_detection_enabled=settings.ml_detection_enabled,
        threat_intel_enrich_on_ingest=settings.threat_intel_enrich_on_ingest,
        soar_enabled=settings.soar_enabled,
        soar_require_approval_for_high_risk=settings.soar_require_approval_for_high_risk,
        notification_channels=list(settings.notification_channels),
        notification_min_severity=settings.notification_min_severity,
        # Booleans, not values: whether a credential is present is useful
        # operational information; the credential itself is not ours to echo.
        notification_webhook_configured=bool(settings.notification_webhook_url),
        smtp_configured=bool(settings.smtp_host),
        auto_create_schema=settings.auto_create_schema,
        metrics_enabled=settings.metrics_enabled,
    )

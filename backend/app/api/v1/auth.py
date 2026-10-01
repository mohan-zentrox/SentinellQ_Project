"""FM1: Tenant signup + local email/password auth + session lifecycle.

Authentication logic lives in `app/services/auth.py` behind the `AuthProvider`
interface; this module is transport only. That is the arrangement the
architecture doc always described -- previously the interface existed but the
route did its own password check inline, so swapping in OIDC would have meant
editing this file.

Session model: a short-lived access token (stateless JWT) plus a long-lived,
single-use, revocable refresh token. Without the refresh token there was no way
to end a session before the access token expired.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import client_ip, get_current_user
from app.core.security import hash_password
from app.db.session import get_db
from app.models.billing import Plan, Subscription
from app.models.tenant import Tenant
from app.models.user import RefreshToken, Role, User
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    SessionOut,
    SignupRequest,
    TokenResponse,
    UserOut,
)
from app.services import auth as auth_service
from app.services.audit import record_audit

router = APIRouter(prefix="/auth", tags=["auth"])


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "tenant"


def _unique_slug(db: Session, base_slug: str) -> str:
    slug = base_slug
    suffix = 1
    while db.query(Tenant).filter(Tenant.slug == slug).first() is not None:
        suffix += 1
        slug = f"{base_slug}-{suffix}"
    return slug


def _token_response(user: User, access: str, refresh: str | None) -> TokenResponse:
    settings = get_settings()
    return TokenResponse(
        access_token=access,
        tenant_id=user.tenant_id,
        user_id=user.id,
        role=user.role,
        refresh_token=refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: SignupRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    """FM1: tenant signup creates a Tenant + its Owner user atomically."""
    email = payload.email.lower()
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    free_plan = db.query(Plan).filter(Plan.slug == get_settings().default_plan_slug).first()

    slug = _unique_slug(db, _slugify(payload.company_name))
    tenant = Tenant(name=payload.company_name, slug=slug, plan_id=free_plan.id if free_plan else None)
    db.add(tenant)
    db.flush()

    if free_plan is not None:
        db.add(Subscription(tenant_id=tenant.id, plan_id=free_plan.id, status="active"))

    user = User(
        tenant_id=tenant.id,
        email=email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=Role.OWNER.value,
        provisioned_by="local",
    )
    db.add(user)
    db.flush()

    access = auth_service.get_auth_provider().issue_token(user)
    refresh = auth_service.issue_refresh_token(
        db,
        user=user,
        user_agent=request.headers.get("user-agent"),
        ip_address=client_ip(request),
    )
    record_audit(
        db,
        tenant_id=tenant.id,
        actor_user_id=user.id,
        action="tenant.created",
        target_type="tenant",
        target_id=tenant.id,
        detail={"slug": slug, "plan": free_plan.slug if free_plan else None},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return _token_response(user, access, refresh)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    ip = client_ip(request)
    try:
        user, access, refresh = auth_service.login(
            db,
            email=payload.email,
            password=payload.password,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
    except auth_service.RateLimited as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except auth_service.AuthError as exc:
        # One message for every failure mode -- wrong password, unknown email,
        # disabled account, SSO-required -- so the response cannot be used to
        # enumerate accounts or probe tenant configuration.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password") from exc

    db.commit()
    db.refresh(user)
    return _token_response(user, access, refresh)


@router.post("/refresh", response_model=TokenResponse)
def refresh_session(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    """Exchange a refresh token for a new access + refresh pair.

    Rotation is single-use. Presenting an already-used token revokes the whole
    session family -- the standard response to a possible token theft -- so a
    401 here can mean "stale token" or "your session was just revoked because
    someone replayed it".
    """
    try:
        user, access, new_refresh = auth_service.rotate_refresh_token(
            db,
            presented=payload.refresh_token,
            user_agent=request.headers.get("user-agent"),
            ip_address=client_ip(request),
        )
    except auth_service.AuthError as exc:
        db.commit()  # persist any family revocation performed during detection
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    db.commit()
    db.refresh(user)
    return _token_response(user, access, new_refresh)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def logout(
    payload: LogoutRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    if payload.all_devices:
        count = auth_service.revoke_all_sessions(db, user=current_user, reason="logout_all")
        record_audit(
            db,
            tenant_id=current_user.tenant_id,
            actor_user_id=current_user.id,
            action="auth.logout_all",
            target_type="user",
            target_id=current_user.id,
            detail={"sessions_revoked": count},
            ip_address=client_ip(request),
        )
    elif payload.refresh_token:
        auth_service.revoke_refresh_token(db, presented=payload.refresh_token, reason="logout")
    else:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Provide refreshToken to end this session, or allDevices=true to end all of them",
        )
    db.commit()


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SessionOut]:
    """Active sessions for the caller -- the "where am I signed in" view.

    Only the caller's own sessions, never another user's, even for an owner:
    a session list is a device/location history, and an admin does not need it
    to manage access (deactivating the user or resetting their password already
    ends every session).
    """
    rows = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.used_at.is_(None),
        )
        .order_by(RefreshToken.issued_at.desc())
        .limit(50)
        .all()
    )
    return [
        SessionOut(
            id=row.id,
            issued_at=row.issued_at,
            expires_at=row.expires_at,
            user_agent=row.user_agent,
            ip_address=row.ip_address,
        )
        for row in rows
    ]


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Change the caller's password. Ends every existing session.

    The client must sign in again afterwards -- including on this device. That
    is intentional: "I changed my password because it may be compromised" has to
    invalidate whatever the other party was holding.
    """
    try:
        auth_service.change_password(
            db,
            user=current_user,
            current_password=payload.current_password,
            new_password=payload.new_password,
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="auth.password_changed",
        target_type="user",
        target_id=current_user.id,
        ip_address=client_ip(request),
    )
    db.commit()


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user

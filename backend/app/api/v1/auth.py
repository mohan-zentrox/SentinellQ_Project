"""FM1: Tenant signup + local email/password auth."""
from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.security import create_access_token, hash_password, verify_password
from app.db.session import get_db
from app.models.billing import Plan, Subscription
from app.models.tenant import Tenant
from app.models.user import Role, User
from app.schemas.auth import LoginRequest, SignupRequest, TokenResponse, UserOut

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


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: SignupRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """FM1: tenant signup creates a Tenant + its Owner user atomically."""
    if db.query(User).filter(User.email == payload.email).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    free_plan = db.query(Plan).filter(Plan.slug == "free").first()

    slug = _unique_slug(db, _slugify(payload.company_name))
    tenant = Tenant(name=payload.company_name, slug=slug, plan_id=free_plan.id if free_plan else None)
    db.add(tenant)
    db.flush()

    if free_plan is not None:
        db.add(Subscription(tenant_id=tenant.id, plan_id=free_plan.id, status="active"))

    user = User(
        tenant_id=tenant.id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=Role.OWNER.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.id, tenant_id=tenant.id, role=user.role)
    return TokenResponse(access_token=token, tenant_id=tenant.id, user_id=user.id, role=user.role)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    # Constant-shape failure path: still run a hash comparison-equivalent op
    # so login timing doesn't trivially reveal whether the email exists.
    if user is None or not verify_password(payload.password, user.hashed_password):
        secrets.compare_digest(payload.password, payload.password)  # no-op timing floor
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User account is disabled")

    token = create_access_token(subject=user.id, tenant_id=user.tenant_id, role=user.role)
    return TokenResponse(access_token=token, tenant_id=user.tenant_id, user_id=user.id, role=user.role)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user

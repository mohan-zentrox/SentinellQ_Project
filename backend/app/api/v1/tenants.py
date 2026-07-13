"""FM1: Tenant self-service + user management (RBAC-gated) + service tokens
for ingestion auth."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, hash_service_token, require_role
from app.core.security import hash_password
from app.db.session import get_db
from app.models.tenant import ServiceToken, Tenant
from app.models.user import Role, User
from app.schemas.auth import UserOut
from app.schemas.tenant import (
    CreateUserRequest,
    ServiceTokenCreateRequest,
    ServiceTokenOut,
    TenantOut,
)

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("/me", response_model=TenantOut)
def get_my_tenant(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Tenant:
    tenant = db.get(Tenant, current_user.tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
    return tenant


@router.get("/me/users", response_model=list[UserOut])
def list_users(
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> list[User]:
    # tenant-scoped: only users belonging to the caller's own tenant.
    return db.query(User).filter(User.tenant_id == current_user.tenant_id).all()


@router.post("/me/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> User:
    if payload.role not in (r.value for r in Role):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid role")
    if db.query(User).filter(User.email == payload.email).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    # Only an owner can create another owner.
    if payload.role == Role.OWNER.value and current_user.role != Role.OWNER.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an owner can grant the owner role")

    user = User(
        tenant_id=current_user.tenant_id,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/me/service-tokens", response_model=ServiceTokenOut, status_code=status.HTTP_201_CREATED)
def create_service_token(
    payload: ServiceTokenCreateRequest,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ServiceTokenOut:
    """Issue a new tenant-scoped bearer credential for machine ingestion
    clients calling POST /v1/events/ingest. The plaintext token is returned
    exactly once; only its hash is persisted.
    """
    plaintext = f"stk_{secrets.token_urlsafe(32)}"
    record = ServiceToken(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        token_hash=hash_service_token(plaintext),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return ServiceTokenOut(id=record.id, name=record.name, token=plaintext)

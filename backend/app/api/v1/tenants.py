"""FM1/FM11: Tenant self-service, user management (RBAC-gated), and service
token lifecycle.

Service tokens previously had a create endpoint and nothing else -- no way to
list what existed or revoke a leaked one, which makes an ingestion credential
effectively permanent. Both are here now.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.deps import client_ip, get_current_user, hash_service_token, require_role
from app.core.security import generate_opaque_token, hash_password
from app.db.session import get_db
from app.models.tenant import ServiceToken, Tenant
from app.models.user import Role, User
from app.schemas.auth import UserOut
from app.schemas.tenant import (
    CreateUserRequest,
    ResetUserPasswordRequest,
    ServiceTokenCreateRequest,
    ServiceTokenOut,
    ServiceTokenSummary,
    TenantOut,
    TenantUpdateRequest,
    UpdateUserRequest,
)
from app.services import auth as auth_service
from app.services.audit import record_audit

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("/me", response_model=TenantOut)
def get_my_tenant(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Tenant:
    tenant = db.get(Tenant, current_user.tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
    return tenant


@router.patch("/me", response_model=TenantOut)
def update_my_tenant(
    payload: TenantUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> Tenant:
    tenant = db.get(Tenant, current_user.tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(tenant, field, value)
    record_audit(
        db,
        tenant_id=tenant.id,
        actor_user_id=current_user.id,
        action="tenant.updated",
        target_type="tenant",
        target_id=tenant.id,
        detail={"fields": sorted(changes)},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(tenant)
    return tenant


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
def _get_owned_user(db: Session, current_user: User, user_id: str) -> User:
    user = db.get(User, user_id)
    if user is None or user.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


@router.get("/me/users", response_model=list[UserOut])
def list_users(
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> list[User]:
    # tenant-scoped: only users belonging to the caller's own tenant.
    return db.query(User).filter(User.tenant_id == current_user.tenant_id).order_by(User.created_at.asc()).all()


@router.post("/me/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> User:
    if payload.role not in (r.value for r in Role):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid role")
    email = payload.email.lower()
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    # Only an owner can create another owner.
    if payload.role == Role.OWNER.value and current_user.role != Role.OWNER.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an owner can grant the owner role")

    user = User(
        tenant_id=current_user.tenant_id,
        email=email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        provisioned_by="local",
    )
    db.add(user)
    db.flush()
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="user.created",
        target_type="user",
        target_id=user.id,
        detail={"email": email, "role": payload.role},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return user


@router.patch("/me/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    payload: UpdateUserRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> User:
    """Change a user's role, name, or active state.

    Guards, each protecting against a way a tenant could lock itself out or
    escalate privilege:
      - only an owner may grant or remove the owner role;
      - you cannot change your own role (no self-promotion, and no accidental
        self-demotion out of the only owner seat);
      - you cannot deactivate yourself;
      - the last active owner cannot be demoted or deactivated.
    """
    target = _get_owned_user(db, current_user, user_id)
    changes = payload.model_dump(exclude_unset=True)

    if "role" in changes:
        new_role = changes["role"]
        if new_role not in (r.value for r in Role):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid role")
        if target.id == current_user.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot change your own role")
        if (new_role == Role.OWNER.value or target.role == Role.OWNER.value) and current_user.role != Role.OWNER.value:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an owner can grant or remove the owner role")

    if changes.get("is_active") is False and target.id == current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot deactivate your own account")

    losing_owner = (changes.get("role") not in (None, Role.OWNER.value) and target.role == Role.OWNER.value) or (
        changes.get("is_active") is False and target.role == Role.OWNER.value
    )
    if losing_owner and _active_owner_count(db, current_user.tenant_id) <= 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This is the tenant's last active owner; promote another owner first",
        )

    for field, value in changes.items():
        setattr(target, field, value)

    if changes.get("is_active") is False:
        from datetime import datetime, timezone

        target.deactivated_at = datetime.now(timezone.utc)
        # A deactivated user must lose access immediately, not whenever their
        # access token happens to expire.
        auth_service.revoke_all_sessions(db, user=target, reason="deactivated")

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="user.updated",
        target_type="user",
        target_id=target.id,
        detail={"fields": sorted(changes), "role": changes.get("role"), "is_active": changes.get("is_active")},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(target)
    return target


@router.post("/me/users/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def reset_user_password(
    user_id: str,
    payload: ResetUserPasswordRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    """Admin-set a user's password and end their sessions.

    An admin cannot reset an owner's password unless they are an owner
    themselves -- otherwise "admin" would be a trivial path to taking over the
    billing-capable account.
    """
    target = _get_owned_user(db, current_user, user_id)
    if target.role == Role.OWNER.value and current_user.role != Role.OWNER.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an owner can reset an owner's password")

    auth_service.set_password_as_admin(db, user=target, new_password=payload.new_password)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="user.password_reset",
        target_type="user",
        target_id=target.id,
        ip_address=client_ip(request),
    )
    db.commit()


def _active_owner_count(db: Session, tenant_id: str) -> int:
    return (
        db.query(User)
        .filter(User.tenant_id == tenant_id, User.role == Role.OWNER.value, User.is_active.is_(True))
        .count()
    )


# --------------------------------------------------------------------------
# Service tokens
# --------------------------------------------------------------------------
@router.get("/me/service-tokens", response_model=list[ServiceTokenSummary])
def list_service_tokens(
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> list[ServiceToken]:
    """List issued ingestion credentials. Never returns token material."""
    return (
        db.query(ServiceToken)
        .filter(ServiceToken.tenant_id == current_user.tenant_id)
        .order_by(ServiceToken.created_at.desc())
        .all()
    )


@router.post("/me/service-tokens", response_model=ServiceTokenOut, status_code=status.HTTP_201_CREATED)
def create_service_token(
    payload: ServiceTokenCreateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ServiceTokenOut:
    """Issue a new tenant-scoped bearer credential for machine ingestion
    clients calling POST /v1/events/ingest. The plaintext token is returned
    exactly once; only its hash is persisted.
    """
    plaintext = f"stk_{generate_opaque_token(32)}"
    record = ServiceToken(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        token_hash=hash_service_token(plaintext),
    )
    db.add(record)
    db.flush()
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="service_token.created",
        target_type="service_token",
        target_id=record.id,
        detail={"name": record.name},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(record)
    return ServiceTokenOut(id=record.id, name=record.name, token=plaintext, created_at=record.created_at)


@router.delete("/me/service-tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def revoke_service_token(
    token_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    """Revoke an ingestion credential.

    Deactivates rather than deletes, so a later "which token was that ingest
    from?" question is still answerable and the audit entry still resolves.
    """
    record = db.get(ServiceToken, token_id)
    if record is None or record.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service token not found")
    record.is_active = False
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="service_token.revoked",
        target_type="service_token",
        target_id=record.id,
        detail={"name": record.name},
        ip_address=client_ip(request),
    )
    db.commit()

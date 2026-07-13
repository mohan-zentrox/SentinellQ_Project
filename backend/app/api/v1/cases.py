"""FM6: Case management -- creation, timeline, assignment, and the
new -> investigating -> resolved/escalated status state machine."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_role
from app.db.session import get_db
from app.models.case import Case, CaseStatus, CaseTimelineEntry
from app.models.user import Role, User
from app.schemas.case import (
    CaseAssignUpdate,
    CaseCreate,
    CaseListResponse,
    CaseOut,
    CaseStatusUpdate,
    CaseTimelineEntryOut,
)

router = APIRouter(prefix="/cases", tags=["cases"])


def _get_owned_case(db: Session, current_user: User, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if case is None or case.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    return case


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Case:
    case = Case(
        tenant_id=current_user.tenant_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        alert_ids=payload.alert_ids,
        status=CaseStatus.NEW,
    )
    db.add(case)
    db.flush()
    db.add(
        CaseTimelineEntry(
            tenant_id=current_user.tenant_id,
            case_id=case.id,
            entry_type="created",
            message="Case created.",
            actor_user_id=current_user.id,
        )
    )
    db.commit()
    db.refresh(case)
    return case


@router.get("", response_model=CaseListResponse)
def list_cases(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CaseListResponse:
    query = db.query(Case).filter(Case.tenant_id == current_user.tenant_id)
    if status_filter:
        query = query.filter(Case.status == status_filter)
    total = query.count()
    rows = query.order_by(Case.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return CaseListResponse(
        total=total, page=page, page_size=page_size, items=[CaseOut.model_validate(r) for r in rows]
    )


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Case:
    return _get_owned_case(db, current_user, case_id)


@router.get("/{case_id}/timeline", response_model=list[CaseTimelineEntryOut])
def get_case_timeline(
    case_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[CaseTimelineEntry]:
    _get_owned_case(db, current_user, case_id)
    return (
        db.query(CaseTimelineEntry)
        .filter(CaseTimelineEntry.tenant_id == current_user.tenant_id, CaseTimelineEntry.case_id == case_id)
        .order_by(CaseTimelineEntry.created_at.asc())
        .all()
    )


@router.patch("/{case_id}/status", response_model=CaseOut)
def update_case_status(
    case_id: str,
    payload: CaseStatusUpdate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Case:
    case = _get_owned_case(db, current_user, case_id)

    if payload.status not in CaseStatus.ALL:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown status: {payload.status}")
    if not CaseStatus.can_transition(case.status, payload.status):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Invalid case status transition: {case.status} -> {payload.status}",
        )

    previous_status = case.status
    case.status = payload.status
    if payload.status == CaseStatus.RESOLVED:
        case.resolved_at = datetime.now(timezone.utc)

    db.add(
        CaseTimelineEntry(
            tenant_id=current_user.tenant_id,
            case_id=case.id,
            entry_type="status_change",
            message=f"Status changed: {previous_status} -> {payload.status}",
            actor_user_id=current_user.id,
        )
    )
    db.commit()
    db.refresh(case)
    return case


@router.patch("/{case_id}/assign", response_model=CaseOut)
def assign_case(
    case_id: str,
    payload: CaseAssignUpdate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Case:
    case = _get_owned_case(db, current_user, case_id)
    case.assignee_user_id = payload.assignee_user_id
    db.add(
        CaseTimelineEntry(
            tenant_id=current_user.tenant_id,
            case_id=case.id,
            entry_type="assignment",
            message=f"Assigned to {payload.assignee_user_id}",
            actor_user_id=current_user.id,
        )
    )
    db.commit()
    db.refresh(case)
    return case

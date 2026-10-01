"""FM6: Case management -- creation, timeline, comments, assignment, and the
new -> investigating -> resolved/escalated status state machine.

Escalating a case is also an FM7 trigger point: `services/soar.py::
trigger_on_case_escalation` runs any playbook bound to `case_escalated`. That
hook is here rather than in the service layer because the transition is what
the operator did, and the automation must observe the same authorization and
tenancy checks the transition did.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.deps import client_ip, get_current_user, require_role
from app.db.session import get_db
from app.models.alert import Alert
from app.models.case import Case, CaseStatus, CaseTimelineEntry
from app.models.user import Role, User
from app.schemas.case import (
    CaseAssignUpdate,
    CaseCommentCreate,
    CaseCreate,
    CaseListResponse,
    CaseOut,
    CaseStatusUpdate,
    CaseTimelineEntryOut,
    CaseUpdate,
)
from app.services.audit import record_audit

router = APIRouter(prefix="/cases", tags=["cases"])


def _get_owned_case(db: Session, current_user: User, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if case is None or case.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")
    return case


def _timeline(
    db: Session,
    *,
    case: Case,
    entry_type: str,
    message: str,
    actor_user_id: str | None,
) -> None:
    db.add(
        CaseTimelineEntry(
            tenant_id=case.tenant_id,
            case_id=case.id,
            entry_type=entry_type,
            message=message[:2000],
            actor_user_id=actor_user_id,
        )
    )


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Case:
    # Any alert ids supplied must belong to the caller's tenant: an unchecked
    # list would let a case cite another tenant's alert ids, and the case detail
    # view would then try to resolve them.
    if payload.alert_ids:
        owned = (
            db.query(Alert.id)
            .filter(Alert.id.in_(payload.alert_ids), Alert.tenant_id == current_user.tenant_id)
            .all()
        )
        owned_ids = {row[0] for row in owned}
        missing = set(payload.alert_ids) - owned_ids
        if missing:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                f"Alert(s) not found in this tenant: {sorted(missing)}",
            )

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
    _timeline(db, case=case, entry_type="created", message="Case created.", actor_user_id=current_user.id)
    db.commit()
    db.refresh(case)
    return case


@router.get("", response_model=CaseListResponse)
def list_cases(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None, pattern="^(informational|low|medium|high|critical)$"),
    assignee_user_id: str | None = Query(default=None, alias="assigneeUserId"),
    unassigned: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CaseListResponse:
    query = db.query(Case).filter(Case.tenant_id == current_user.tenant_id)
    if status_filter:
        if status_filter not in CaseStatus.ALL:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Unknown status {status_filter!r}. Valid: {', '.join(CaseStatus.ALL)}",
            )
        query = query.filter(Case.status == status_filter)
    if severity:
        query = query.filter(Case.severity == severity)
    if assignee_user_id:
        query = query.filter(Case.assignee_user_id == assignee_user_id)
    if unassigned:
        query = query.filter(Case.assignee_user_id.is_(None))

    total = query.count()
    rows = query.order_by(Case.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return CaseListResponse(
        total=total, page=page, page_size=page_size, items=[CaseOut.model_validate(r) for r in rows]
    )


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Case:
    return _get_owned_case(db, current_user, case_id)


@router.patch("/{case_id}", response_model=CaseOut)
def update_case(
    case_id: str,
    payload: CaseUpdate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Case:
    case = _get_owned_case(db, current_user, case_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(case, field, value)
    if changes:
        _timeline(
            db,
            case=case,
            entry_type="comment",
            message=f"Case fields updated: {', '.join(sorted(changes))}.",
            actor_user_id=current_user.id,
        )
    db.commit()
    db.refresh(case)
    return case


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


@router.post(
    "/{case_id}/comments",
    response_model=CaseTimelineEntryOut,
    status_code=status.HTTP_201_CREATED,
)
def add_case_comment(
    case_id: str,
    payload: CaseCommentCreate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> CaseTimelineEntry:
    """Add an analyst note to the case timeline.

    The timeline model has always supported a `comment` entry type, but only
    automated transitions could write one -- an analyst had no way to record what
    they found, which is most of what case work actually is.
    """
    case = _get_owned_case(db, current_user, case_id)
    entry = CaseTimelineEntry(
        tenant_id=current_user.tenant_id,
        case_id=case.id,
        entry_type="comment",
        message=payload.message,
        actor_user_id=current_user.id,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.patch("/{case_id}/status", response_model=CaseOut)
def update_case_status(
    case_id: str,
    payload: CaseStatusUpdate,
    request: Request,
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

    message = f"Status changed: {previous_status} -> {payload.status}"
    if payload.note:
        message = f"{message}. {payload.note}"
    _timeline(db, case=case, entry_type="status_change", message=message, actor_user_id=current_user.id)

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="case.status_changed",
        target_type="case",
        target_id=case.id,
        detail={"from": previous_status, "to": payload.status},
        ip_address=client_ip(request),
    )

    # FM7 trigger point: escalation can start a playbook.
    if payload.status == CaseStatus.ESCALATED:
        from app.core.config import get_settings

        if get_settings().soar_enabled:
            try:
                from app.services.soar import trigger_on_case_escalation

                trigger_on_case_escalation(
                    db,
                    tenant_id=current_user.tenant_id,
                    case=case,
                    actor_user_id=current_user.id,
                )
            except Exception:  # noqa: BLE001 - automation must not block the transition
                import logging

                logging.getLogger(__name__).exception(
                    "cases.escalation_automation_failed",
                    extra={"tenant_id": current_user.tenant_id, "case_id": case.id},
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
    """Assign or unassign a case.

    The assignee must be an active user in the caller's own tenant. Previously
    any string was accepted, so a typo silently black-holed the case (nothing
    showed it as unassigned) and a cross-tenant id would have been stored
    verbatim.
    """
    case = _get_owned_case(db, current_user, case_id)

    if payload.assignee_user_id is None:
        case.assignee_user_id = None
        _timeline(db, case=case, entry_type="assignment", message="Case unassigned.", actor_user_id=current_user.id)
    else:
        assignee = db.get(User, payload.assignee_user_id)
        if assignee is None or assignee.tenant_id != current_user.tenant_id or not assignee.is_active:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "Assignee is not an active user in this tenant",
            )
        case.assignee_user_id = assignee.id
        _timeline(
            db,
            case=case,
            entry_type="assignment",
            message=f"Assigned to {assignee.email}",
            actor_user_id=current_user.id,
        )

    db.commit()
    db.refresh(case)
    return case

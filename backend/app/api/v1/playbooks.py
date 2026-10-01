"""FM7: SOAR playbook API.

Approval endpoints are the security-relevant part. A run whose playbook
contains a high-risk action is created in `pending_approval` and only executes
once a human POSTs to `/approve`; the engine
(`services/soar.py::execute_run`) refuses otherwise, so this API cannot be
bypassed by a different caller.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import client_ip, get_current_user, require_role
from app.db.session import get_db
from app.models.alert import Alert
from app.models.case import Case
from app.models.soar import Playbook, PlaybookActionRecord, PlaybookRun, PlaybookTrigger, RunStatus
from app.models.user import Role, User
from app.schemas.soar import (
    ActionRecordOut,
    ActionRegistryEntry,
    PlaybookCreate,
    PlaybookOut,
    PlaybookRunDetailOut,
    PlaybookRunListResponse,
    PlaybookRunOut,
    PlaybookUpdate,
    RejectRunRequest,
    RunPlaybookRequest,
)
from app.services.audit import record_audit
from app.services.rule_engine import ConditionError, validate_condition
from app.services.soar import (
    ApprovalRequired,
    approve_run,
    create_run,
    describe_actions,
    execute_run,
    playbook_requires_approval,
    reject_run,
    validate_actions,
)

router = APIRouter(tags=["playbooks"])


def _to_out(playbook: Playbook) -> PlaybookOut:
    out = PlaybookOut.model_validate(playbook)
    out.requires_approval = playbook_requires_approval(playbook)
    return out


def _get_owned_playbook(db: Session, current_user: User, playbook_id: str) -> Playbook:
    playbook = db.get(Playbook, playbook_id)
    if playbook is None or playbook.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found")
    return playbook


def _get_owned_run(db: Session, current_user: User, run_id: str) -> PlaybookRun:
    run = db.get(PlaybookRun, run_id)
    if run is None or run.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook run not found")
    return run


def _validate(actions: list[dict], trigger_condition: dict | None) -> None:
    try:
        validate_actions(actions)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if trigger_condition is not None:
        try:
            validate_condition(trigger_condition)
        except ConditionError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid trigger condition: {exc}"
            ) from exc


@router.get("/playbook-actions", response_model=list[ActionRegistryEntry])
def list_available_actions(
    current_user: User = Depends(get_current_user),
) -> list[ActionRegistryEntry]:
    """The action registry, for the playbook-authoring UI.

    `isHighRisk` is what the UI uses to warn the author that this playbook will
    require per-run approval.
    """
    return [ActionRegistryEntry(**entry) for entry in describe_actions()]


@router.get("/playbooks", response_model=list[PlaybookOut])
def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[PlaybookOut]:
    rows = (
        db.query(Playbook)
        .filter(Playbook.tenant_id == current_user.tenant_id)
        .order_by(Playbook.created_at.desc())
        .all()
    )
    return [_to_out(row) for row in rows]


@router.post("/playbooks", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED)
def create_playbook(
    payload: PlaybookCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> PlaybookOut:
    """Create a playbook. Admin+ only -- automation that acts on a tenant's data
    is a privileged configuration change, not analyst work."""
    actions = [action.model_dump(by_alias=False) for action in payload.actions]
    _validate(actions, payload.trigger_condition)

    playbook = Playbook(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        description=payload.description,
        trigger=payload.trigger,
        trigger_condition=payload.trigger_condition,
        actions=actions,
        is_enabled=payload.is_enabled,
        dry_run=payload.dry_run,
        created_by_user_id=current_user.id,
    )
    db.add(playbook)
    db.flush()
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="playbook.created",
        target_type="playbook",
        target_id=playbook.id,
        detail={
            "name": playbook.name,
            "trigger": playbook.trigger,
            "actions": [a["action"] for a in actions],
            "dry_run": playbook.dry_run,
        },
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(playbook)
    return _to_out(playbook)


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut)
def get_playbook(
    playbook_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookOut:
    return _to_out(_get_owned_playbook(db, current_user, playbook_id))


@router.patch("/playbooks/{playbook_id}", response_model=PlaybookOut)
def update_playbook(
    playbook_id: str,
    payload: PlaybookUpdate,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> PlaybookOut:
    playbook = _get_owned_playbook(db, current_user, playbook_id)
    changes = payload.model_dump(exclude_unset=True)

    if "actions" in changes and changes["actions"] is not None:
        changes["actions"] = [
            action if isinstance(action, dict) else action.model_dump(by_alias=False)
            for action in changes["actions"]
        ]
    _validate(
        changes.get("actions", playbook.actions),
        changes.get("trigger_condition", playbook.trigger_condition),
    )

    for field, value in changes.items():
        setattr(playbook, field, value)

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="playbook.updated",
        target_type="playbook",
        target_id=playbook.id,
        detail={"fields": sorted(changes)},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(playbook)
    return _to_out(playbook)


@router.delete("/playbooks/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_playbook(
    playbook_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    """Delete a playbook. Its run history is retained as an automation audit
    trail -- "what did the automation do to this case?" must stay answerable
    after someone deletes the playbook."""
    playbook = _get_owned_playbook(db, current_user, playbook_id)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="playbook.deleted",
        target_type="playbook",
        target_id=playbook.id,
        detail={"name": playbook.name},
        ip_address=client_ip(request),
    )
    db.delete(playbook)
    db.commit()


@router.post("/playbooks/{playbook_id}/run", response_model=PlaybookRunOut, status_code=status.HTTP_201_CREATED)
def run_playbook(
    playbook_id: str,
    payload: RunPlaybookRequest,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> PlaybookRun:
    """Trigger a playbook manually against an alert or case.

    Returns 201 with `status: "pending_approval"` when the playbook contains a
    high-risk action -- the run exists but nothing has executed yet.
    """
    playbook = _get_owned_playbook(db, current_user, playbook_id)

    alert: Alert | None = None
    case: Case | None = None
    if payload.alert_id:
        alert = db.get(Alert, payload.alert_id)
        if alert is None or alert.tenant_id != current_user.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    if payload.case_id:
        case = db.get(Case, payload.case_id)
        if case is None or case.tenant_id != current_user.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Case not found")

    run = create_run(
        db,
        playbook=playbook,
        trigger=PlaybookTrigger.MANUAL,
        alert=alert,
        case=case,
        triggered_by_user_id=current_user.id,
    )
    if not run.requires_approval:
        try:
            execute_run(db, run=run, playbook=playbook, alert=alert, case=case)
        except ApprovalRequired as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    db.commit()
    db.refresh(run)
    return run


@router.get("/playbook-runs", response_model=PlaybookRunListResponse)
def list_runs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    run_status: str | None = Query(default=None, alias="status"),
    playbook_id: str | None = Query(default=None, alias="playbookId"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookRunListResponse:
    query = db.query(PlaybookRun).filter(PlaybookRun.tenant_id == current_user.tenant_id)
    if run_status:
        if run_status not in RunStatus.ALL:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Unknown status {run_status!r}. Valid: {', '.join(RunStatus.ALL)}",
            )
        query = query.filter(PlaybookRun.status == run_status)
    if playbook_id:
        query = query.filter(PlaybookRun.playbook_id == playbook_id)

    total = query.count()
    rows = (
        query.order_by(PlaybookRun.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PlaybookRunListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[PlaybookRunOut.model_validate(row) for row in rows],
    )


@router.get("/playbook-runs/{run_id}", response_model=PlaybookRunDetailOut)
def get_run(
    run_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookRunDetailOut:
    run = _get_owned_run(db, current_user, run_id)
    records = list(
        db.execute(
            select(PlaybookActionRecord)
            .where(
                PlaybookActionRecord.tenant_id == current_user.tenant_id,
                PlaybookActionRecord.run_id == run.id,
            )
            .order_by(PlaybookActionRecord.sequence.asc())
        ).scalars()
    )
    detail = PlaybookRunDetailOut.model_validate(run)
    detail.actions = [ActionRecordOut.model_validate(record) for record in records]
    return detail


@router.post("/playbook-runs/{run_id}/approve", response_model=PlaybookRunDetailOut)
def approve_playbook_run(
    run_id: str,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> PlaybookRunDetailOut:
    """Approve a pending run and execute it immediately.

    Admin+ only, and never the automation itself: this endpoint is the human in
    "human-in-the-loop". The approver is recorded on the run and on every action
    record it produces.
    """
    run = _get_owned_run(db, current_user, run_id)
    playbook = db.get(Playbook, run.playbook_id)
    if playbook is None or playbook.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook for this run no longer exists")

    try:
        approve_run(db, run=run, playbook=playbook, approver_user_id=current_user.id)
    except ApprovalRequired as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    db.commit()
    db.refresh(run)
    return get_run(run_id=run.id, current_user=current_user, db=db)


@router.post("/playbook-runs/{run_id}/reject", response_model=PlaybookRunOut)
def reject_playbook_run(
    run_id: str,
    payload: RejectRunRequest,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> PlaybookRun:
    run = _get_owned_run(db, current_user, run_id)
    try:
        reject_run(db, run=run, rejecter_user_id=current_user.id, reason=payload.reason)
    except ApprovalRequired as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    db.refresh(run)
    return run

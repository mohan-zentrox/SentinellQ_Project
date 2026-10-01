"""FM4 (rules part): DetectionRule CRUD + evaluator trigger endpoints.
URL uses the kebab-case resource name `detection-rules`.

Conditions are validated structurally at create/update time
(`rule_engine.validate_condition`) so a malformed rule is rejected with a 422
describing the problem, rather than being stored and then silently failing --
or taking down a whole run-all -- during a later evaluation.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_role
from app.db.session import get_db
from app.models.event import Event
from app.models.rule import DetectionRule, RuleEventMatch
from app.models.user import Role, User
from app.schemas.rule import (
    DetectionRuleCreate,
    DetectionRuleOut,
    DetectionRuleUpdate,
    RuleRunResponse,
    RuleTestRequest,
    RuleTestResponse,
)
from app.services.audit import record_audit
from app.services.rule_engine import (
    ConditionError,
    evaluate_rule_over_events,
    run_all_rules,
    run_rule,
    validate_condition,
)
from app.services.telemetry_store import get_telemetry_store

router = APIRouter(prefix="/detection-rules", tags=["detection-rules"])


def _validated(condition: dict) -> dict:
    try:
        validate_condition(condition)
    except ConditionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid rule condition: {exc}") from exc
    return condition


def _get_owned_rule(db: Session, current_user: User, rule_id: str) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if rule is None or rule.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection rule not found")
    return rule


@router.post("", response_model=DetectionRuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: DetectionRuleCreate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        description=payload.description,
        condition=_validated(payload.condition),
        severity=payload.severity,
        is_enabled=payload.is_enabled,
        evaluation_window_minutes=payload.evaluation_window_minutes,
        created_by_user_id=current_user.id,
    )
    db.add(rule)
    db.flush()
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="detection_rule.created",
        target_type="detection_rule",
        target_id=rule.id,
        detail={"name": rule.name, "severity": rule.severity},
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.get("", response_model=list[DetectionRuleOut])
def list_rules(
    enabled: bool | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DetectionRule]:
    query = db.query(DetectionRule).filter(DetectionRule.tenant_id == current_user.tenant_id)
    if enabled is not None:
        query = query.filter(DetectionRule.is_enabled.is_(enabled))
    return query.order_by(DetectionRule.created_at.desc()).all()


@router.get("/{rule_id}", response_model=DetectionRuleOut)
def get_rule(
    rule_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> DetectionRule:
    return _get_owned_rule(db, current_user, rule_id)


@router.patch("/{rule_id}", response_model=DetectionRuleOut)
def update_rule(
    rule_id: str,
    payload: DetectionRuleUpdate,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> DetectionRule:
    rule = _get_owned_rule(db, current_user, rule_id)
    changes = payload.model_dump(exclude_unset=True)
    if "condition" in changes:
        _validated(changes["condition"])
    for field, value in changes.items():
        setattr(rule, field, value)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="detection_rule.updated",
        target_type="detection_rule",
        target_id=rule.id,
        detail={"fields": sorted(changes)},
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_rule(
    rule_id: str,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    """Delete a rule and its dedup ledger.

    Alerts the rule already produced are deliberately kept: they are
    historical findings an analyst may still be working, and silently deleting
    an investigation's evidence because someone tidied up a rule would be
    worse than leaving an alert whose rule_id no longer resolves. The rule's
    `rule_event_matches` rows go, because without them a recreated rule with
    the same id could never re-alert.
    """
    rule = _get_owned_rule(db, current_user, rule_id)
    db.query(RuleEventMatch).filter(
        RuleEventMatch.tenant_id == current_user.tenant_id,
        RuleEventMatch.rule_id == rule.id,
    ).delete(synchronize_session=False)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="detection_rule.deleted",
        target_type="detection_rule",
        target_id=rule.id,
        detail={"name": rule.name},
    )
    db.delete(rule)
    db.commit()


@router.post("/test", response_model=RuleTestResponse)
def test_rule(
    payload: RuleTestRequest = Body(...),
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> RuleTestResponse:
    """Dry-run a condition against recent events without creating alerts.

    This is what makes the rules UI usable: an analyst can see how many of the
    last N events a condition would match before enabling it, instead of
    enabling it in production and finding out from the alert volume.
    """
    _validated(payload.condition)
    store = get_telemetry_store()
    events: list[Event] = store.events_since(
        db, tenant_id=current_user.tenant_id, since=None, limit=payload.sample_size
    )

    # A throwaway, unsaved rule so windowed conditions evaluate identically to
    # the real path.
    probe = DetectionRule(
        tenant_id=current_user.tenant_id,
        name="__test__",
        condition=payload.condition,
        severity="medium",
    )
    try:
        matched = evaluate_rule_over_events(probe, events)
    except ConditionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid rule condition: {exc}") from exc

    return RuleTestResponse(
        sampled=len(events),
        matched=len(matched),
        matched_event_ids=matched[:50],
    )


@router.post("/{rule_id}/run", response_model=RuleRunResponse)
def run_single_rule(
    rule_id: str,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> RuleRunResponse:
    rule = _get_owned_rule(db, current_user, rule_id)
    try:
        alert = run_rule(db, tenant_id=current_user.tenant_id, rule=rule)
    except ConditionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Invalid rule condition: {exc}") from exc

    alerts = [alert] if alert is not None else []
    _post_run_side_effects(db, tenant_id=current_user.tenant_id, alerts=alerts)
    db.commit()
    return RuleRunResponse(alerts_created=len(alerts), alert_ids=[a.id for a in alerts])


@router.post("/run-all", response_model=RuleRunResponse)
def run_all(
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> RuleRunResponse:
    alerts = run_all_rules(db, tenant_id=current_user.tenant_id)
    _post_run_side_effects(db, tenant_id=current_user.tenant_id, alerts=alerts)
    db.commit()
    return RuleRunResponse(alerts_created=len(alerts), alert_ids=[a.id for a in alerts])


def _post_run_side_effects(db: Session, *, tenant_id: str, alerts: list) -> None:
    """Manually-triggered runs must notify and automate exactly like the
    ingest-triggered path, or an on-call would be paged for an alert found by
    the worker but not for the same alert found by an analyst's run-all."""
    if not alerts:
        return
    from app.services.pipeline import notify_and_automate

    notify_and_automate(db, tenant_id=tenant_id, alerts=alerts)

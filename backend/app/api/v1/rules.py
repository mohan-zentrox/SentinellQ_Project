"""FM4 (rules part): DetectionRule CRUD + evaluator trigger endpoints.
URL uses the kebab-case resource name `detection-rules`."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_role
from app.db.session import get_db
from app.models.rule import DetectionRule
from app.models.user import Role, User
from app.schemas.rule import DetectionRuleCreate, DetectionRuleOut, RuleRunResponse
from app.services.rule_engine import run_all_rules, run_rule

router = APIRouter(prefix="/detection-rules", tags=["detection-rules"])


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
        condition=payload.condition,
        severity=payload.severity,
        is_enabled=payload.is_enabled,
        created_by_user_id=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.get("", response_model=list[DetectionRuleOut])
def list_rules(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[DetectionRule]:
    return db.query(DetectionRule).filter(DetectionRule.tenant_id == current_user.tenant_id).all()


def _get_owned_rule(db: Session, current_user: User, rule_id: str) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if rule is None or rule.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Detection rule not found")
    return rule


@router.get("/{rule_id}", response_model=DetectionRuleOut)
def get_rule(
    rule_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> DetectionRule:
    return _get_owned_rule(db, current_user, rule_id)


@router.post("/{rule_id}/run", response_model=RuleRunResponse)
def run_single_rule(
    rule_id: str,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> RuleRunResponse:
    rule = _get_owned_rule(db, current_user, rule_id)
    alert = run_rule(db, tenant_id=current_user.tenant_id, rule=rule)
    db.commit()
    if alert is None:
        return RuleRunResponse(alerts_created=0, alert_ids=[])
    return RuleRunResponse(alerts_created=1, alert_ids=[alert.id])


@router.post("/run-all", response_model=RuleRunResponse)
def run_all(
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> RuleRunResponse:
    alerts = run_all_rules(db, tenant_id=current_user.tenant_id)
    db.commit()
    return RuleRunResponse(alerts_created=len(alerts), alert_ids=[a.id for a in alerts])

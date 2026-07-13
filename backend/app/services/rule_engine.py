"""FM4: Detection rule evaluator (rules-based part; ML scoring is scaffolded
separately under app/scaffold/ml_detection/).

Condition DSL (stored as JSON on DetectionRule.condition):

  Leaf:   {"field": "severity_hint", "op": "eq", "value": "critical"}
  AND:    {"all": [<condition>, <condition>, ...]}
  OR:     {"any": [<condition>, <condition>, ...]}

Supported operators: eq, neq, contains, in, gt, gte, lt, lte.
`field` is looked up on the normalized event's flat attributes first
(event_category, event_action, severity_hint, actor, target, source_ip),
falling back to the nested `normalized` document.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import DetectionRule

_FLAT_FIELDS = {"event_category", "event_action", "severity_hint", "actor", "target", "source_ip"}


class ConditionError(ValueError):
    pass


def _resolve_field(event: Event, field: str) -> Any:
    if field in _FLAT_FIELDS:
        return getattr(event, field)
    # dotted-path lookup into the nested normalized document, e.g. "event.kind"
    node: Any = event.normalized or {}
    for part in field.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        else:
            return None
    return node


def _apply_op(actual: Any, op: str, expected: Any) -> bool:
    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "contains":
        return actual is not None and expected in actual
    if op == "in":
        return actual in (expected or [])
    if op == "gt":
        return actual is not None and actual > expected
    if op == "gte":
        return actual is not None and actual >= expected
    if op == "lt":
        return actual is not None and actual < expected
    if op == "lte":
        return actual is not None and actual <= expected
    raise ConditionError(f"Unsupported operator: {op!r}")


def evaluate_condition(condition: dict[str, Any], event: Event) -> bool:
    if not isinstance(condition, dict):
        raise ConditionError("condition must be a JSON object")

    if "all" in condition:
        return all(evaluate_condition(sub, event) for sub in condition["all"])
    if "any" in condition:
        return any(evaluate_condition(sub, event) for sub in condition["any"])

    if "field" not in condition or "op" not in condition:
        raise ConditionError("leaf condition requires 'field' and 'op'")

    actual = _resolve_field(event, condition["field"])
    return _apply_op(actual, condition["op"], condition.get("value"))


def run_rule(db: Session, *, tenant_id: str, rule: DetectionRule, events: list[Event] | None = None) -> Alert | None:
    """Evaluate a single rule against all (or a supplied subset of) a
    tenant's events. Creates and returns a new Alert when there are matches
    that aren't already covered by an existing open alert for this rule;
    returns None otherwise.
    """
    if events is None:
        events = list(db.execute(select(Event).where(Event.tenant_id == tenant_id)).scalars().all())

    matched_ids = [e.id for e in events if evaluate_condition(rule.condition, e)]
    if not matched_ids:
        return None

    existing_alerted_ids: set[str] = set()
    for existing in db.execute(
        select(Alert).where(Alert.tenant_id == tenant_id, Alert.rule_id == rule.id)
    ).scalars():
        existing_alerted_ids.update(existing.event_ids)

    new_matches = [eid for eid in matched_ids if eid not in existing_alerted_ids]
    if not new_matches:
        return None

    alert = Alert(
        tenant_id=tenant_id,
        rule_id=rule.id,
        title=f"Rule triggered: {rule.name}",
        description=rule.description or f"Detection rule '{rule.name}' matched {len(new_matches)} event(s).",
        severity=rule.severity,
        status="open",
        event_ids=new_matches,
    )
    db.add(alert)
    db.flush()
    return alert


def run_all_rules(db: Session, *, tenant_id: str) -> list[Alert]:
    events = list(db.execute(select(Event).where(Event.tenant_id == tenant_id)).scalars().all())
    rules = list(
        db.execute(
            select(DetectionRule).where(DetectionRule.tenant_id == tenant_id, DetectionRule.is_enabled.is_(True))
        ).scalars()
    )
    created: list[Alert] = []
    for rule in rules:
        alert = run_rule(db, tenant_id=tenant_id, rule=rule, events=events)
        if alert is not None:
            created.append(alert)
    return created

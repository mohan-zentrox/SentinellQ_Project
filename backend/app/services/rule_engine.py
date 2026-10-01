"""FM4: Detection rule evaluator (rules-based part; ML scoring lives in
app/services/ml_detection.py).

Condition DSL (stored as JSON on DetectionRule.condition):

  Leaf:   {"field": "severity_hint", "op": "eq", "value": "critical"}
  AND:    {"all": [<condition>, <condition>, ...]}
  OR:     {"any": [<condition>, <condition>, ...]}
  NOT:    {"not": <condition>}

Supported operators: eq, neq, contains, icontains, in, not_in, gt, gte, lt,
lte, regex, exists, cidr.

`field` is looked up on the normalized event's flat attributes
(event_category, event_action, severity_hint, actor, target, source_ip),
falling back to a dotted path into the nested `normalized` document, and then
into `enrichment` (so FM5 threat-intel annotations are rule-addressable, e.g.
`{"field": "enrichment.maxConfidence", "op": "gte", "value": 80}`).

A leaf may additionally carry a `window`, which turns it from a per-event
predicate into a threshold over time:

  {"field": "event_action", "op": "eq", "value": "login_failed",
   "window": {"minutes": 10, "count": 5, "groupBy": "actor"}}

reads as "5+ matching events within any 10-minute span, grouped by actor".
Windowed leaves are evaluated across the candidate set rather than per event,
so they only appear at the top level or under `all`/`any` (a windowed leaf
nested under `not` is rejected -- negating a threshold is ambiguous).

Scan bounding: no evaluation ever loads a tenant's whole event corpus.
`run_rule` reads at most `settings.detection_max_scan_events` events, and only
those inside the rule's `evaluation_window_minutes` (falling back to
`settings.detection_default_window_minutes`).

Dedup: `rule_event_matches` is the authority for "already alerted on this
(rule, event)". Its unique constraint also makes concurrent workers safe --
the loser of a race gets an IntegrityError and skips rather than
double-alerting.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import DetectionRule, RuleEventMatch
from app.services.telemetry_store import get_telemetry_store

logger = logging.getLogger(__name__)

_FLAT_FIELDS = {"event_category", "event_action", "severity_hint", "actor", "target", "source_ip", "source"}

#: Regex compilation is the expensive part of a regex rule; rules are
#: long-lived and few, so caching compiled patterns across evaluations is a
#: large win on a run-all over thousands of events.
_REGEX_CACHE_SIZE = 512


class ConditionError(ValueError):
    """Raised for a malformed condition. Surfaced as a 422 by the API layer."""


@lru_cache(maxsize=_REGEX_CACHE_SIZE)
def _compile(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ConditionError(f"invalid regex {pattern!r}: {exc}") from exc


def _resolve_field(event: Event, field: str) -> Any:
    if field in _FLAT_FIELDS:
        return getattr(event, field)
    # Dotted-path lookup: "normalized"/"enrichment" prefixes are explicit, a
    # bare dotted path falls back to the normalized document (the pre-existing
    # behaviour, kept so existing rules keep working).
    root, _, rest = field.partition(".")
    if root == "enrichment":
        node: Any = event.enrichment or {}
        path = rest
    elif root == "normalized":
        node = event.normalized or {}
        path = rest
    else:
        node = event.normalized or {}
        path = field
    if not path:
        return node
    for part in path.split("."):
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list):
            # Allow a leaf to address list membership, e.g. enrichment.tags
            return [item.get(part) if isinstance(item, dict) else None for item in node]
        else:
            return None
    return node


def _coerce_comparable(actual: Any, expected: Any) -> tuple[Any, Any]:
    """Make ordered comparisons work across the JSON/column type boundary.

    A rule authored in the UI may carry `{"value": 80}` while the event's
    enrichment holds `"80"` (or vice versa, since JSON columns round-trip
    loosely through SQLite). Rather than silently returning False on a type
    mismatch -- the failure mode that makes a detection rule quietly stop
    firing -- try a numeric coercion first and fall back to string compare.
    """
    if type(actual) is type(expected):
        return actual, expected
    if isinstance(actual, bool) or isinstance(expected, bool):
        return actual, expected
    for caster in (int, float):
        try:
            return caster(actual), caster(expected)
        except (TypeError, ValueError):
            continue
    return str(actual), str(expected)


def _apply_op(actual: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        present = actual is not None and actual != [] and actual != {}
        return present if expected in (None, True) else not present
    if op == "eq":
        return actual == expected
    if op == "neq":
        return actual != expected
    if op == "contains":
        if actual is None:
            return False
        try:
            return expected in actual
        except TypeError:
            return False
    if op == "icontains":
        if actual is None or expected is None:
            return False
        return str(expected).lower() in str(actual).lower()
    if op == "in":
        if isinstance(actual, list):
            return any(item in (expected or []) for item in actual)
        return actual in (expected or [])
    if op == "not_in":
        if isinstance(actual, list):
            return not any(item in (expected or []) for item in actual)
        return actual not in (expected or [])
    if op == "regex":
        if actual is None:
            return False
        return _compile(str(expected)).search(str(actual)) is not None
    if op == "cidr":
        if actual is None:
            return False
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            # A malformed address on the event is a non-match; a malformed
            # network in the rule is an authoring error worth surfacing.
            try:
                ipaddress.ip_network(str(expected), strict=False)
            except ValueError as exc:
                raise ConditionError(f"invalid CIDR {expected!r}: {exc}") from exc
            return False
    if op in {"gt", "gte", "lt", "lte"}:
        if actual is None:
            return False
        left, right = _coerce_comparable(actual, expected)
        try:
            if op == "gt":
                return left > right
            if op == "gte":
                return left >= right
            if op == "lt":
                return left < right
            return left <= right
        except TypeError:
            return False
    raise ConditionError(f"Unsupported operator: {op!r}")


def _is_windowed(condition: dict[str, Any]) -> bool:
    return isinstance(condition, dict) and isinstance(condition.get("window"), dict)


def evaluate_condition(condition: dict[str, Any], event: Event) -> bool:
    """Per-event evaluation. Windowed leaves are ignored here (they are
    threshold predicates over a set, handled by `evaluate_rule_over_events`);
    a windowed leaf evaluates as its underlying per-event predicate so that
    `_candidates` can pre-filter cheaply.
    """
    if not isinstance(condition, dict):
        raise ConditionError("condition must be a JSON object")

    if "all" in condition:
        subs = condition["all"]
        if not isinstance(subs, list) or not subs:
            raise ConditionError("'all' requires a non-empty list of conditions")
        return all(evaluate_condition(sub, event) for sub in subs)
    if "any" in condition:
        subs = condition["any"]
        if not isinstance(subs, list) or not subs:
            raise ConditionError("'any' requires a non-empty list of conditions")
        return any(evaluate_condition(sub, event) for sub in subs)
    if "not" in condition:
        sub = condition["not"]
        if _is_windowed(sub):
            raise ConditionError("'not' cannot negate a windowed condition; invert the threshold instead")
        return not evaluate_condition(sub, event)

    if "field" not in condition or "op" not in condition:
        raise ConditionError("leaf condition requires 'field' and 'op'")

    actual = _resolve_field(event, condition["field"])
    return _apply_op(actual, condition["op"], condition.get("value"))


def validate_condition(condition: Any) -> None:
    """Structural validation without an event. Used by the rules API so a
    malformed rule is rejected at create/update time (422) rather than
    exploding during a later evaluation.
    """
    if not isinstance(condition, dict):
        raise ConditionError("condition must be a JSON object")
    if "all" in condition or "any" in condition:
        key = "all" if "all" in condition else "any"
        subs = condition[key]
        if not isinstance(subs, list) or not subs:
            raise ConditionError(f"'{key}' requires a non-empty list of conditions")
        for sub in subs:
            validate_condition(sub)
        return
    if "not" in condition:
        if _is_windowed(condition["not"]):
            raise ConditionError("'not' cannot negate a windowed condition; invert the threshold instead")
        validate_condition(condition["not"])
        return
    if "field" not in condition or "op" not in condition:
        raise ConditionError("leaf condition requires 'field' and 'op'")
    if not isinstance(condition["field"], str) or not condition["field"]:
        raise ConditionError("'field' must be a non-empty string")
    op = condition["op"]
    if op not in _SUPPORTED_OPS:
        raise ConditionError(f"Unsupported operator: {op!r}. Supported: {', '.join(sorted(_SUPPORTED_OPS))}")
    if op == "regex":
        _compile(str(condition.get("value", "")))
    if op == "cidr":
        try:
            ipaddress.ip_network(str(condition.get("value")), strict=False)
        except ValueError as exc:
            raise ConditionError(f"invalid CIDR {condition.get('value')!r}: {exc}") from exc
    if op in {"in", "not_in"} and not isinstance(condition.get("value"), list):
        raise ConditionError(f"operator {op!r} requires a list 'value'")
    window = condition.get("window")
    if window is not None:
        if not isinstance(window, dict):
            raise ConditionError("'window' must be an object")
        minutes = window.get("minutes")
        count = window.get("count")
        if not isinstance(minutes, int) or minutes <= 0:
            raise ConditionError("window.minutes must be a positive integer")
        if not isinstance(count, int) or count < 2:
            raise ConditionError("window.count must be an integer >= 2 (a count of 1 is just a plain leaf)")
        group_by = window.get("groupBy")
        if group_by is not None and not isinstance(group_by, str):
            raise ConditionError("window.groupBy must be a string field name")


_SUPPORTED_OPS = {
    "eq",
    "neq",
    "contains",
    "icontains",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "regex",
    "exists",
    "cidr",
}


def _collect_windows(condition: dict[str, Any]) -> list[dict[str, Any]]:
    """Every windowed leaf in the tree, in document order."""
    found: list[dict[str, Any]] = []
    if not isinstance(condition, dict):
        return found
    if _is_windowed(condition):
        found.append(condition)
        return found
    for key in ("all", "any"):
        if isinstance(condition.get(key), list):
            for sub in condition[key]:
                found.extend(_collect_windows(sub))
    return found


def _occurred_at(event: Event) -> datetime:
    value = event.occurred_at
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _apply_window(leaf: dict[str, Any], events: list[Event]) -> list[str]:
    """Return the ids of events that participate in a satisfied threshold.

    Sliding window over events sorted by occurred_at: for each group, any span
    of `minutes` containing >= `count` matching events contributes all events
    in that span.
    """
    window = leaf["window"]
    span = timedelta(minutes=int(window["minutes"]))
    threshold = int(window["count"])
    group_by = window.get("groupBy")

    matching = [e for e in events if evaluate_condition({k: v for k, v in leaf.items() if k != "window"}, e)]
    matching.sort(key=_occurred_at)

    groups: dict[Any, list[Event]] = defaultdict(list)
    for event in matching:
        key = _resolve_field(event, group_by) if group_by else None
        groups[key].append(event)

    participating: set[str] = set()
    for bucket in groups.values():
        left = 0
        for right in range(len(bucket)):
            while _occurred_at(bucket[right]) - _occurred_at(bucket[left]) > span:
                left += 1
            if right - left + 1 >= threshold:
                participating.update(e.id for e in bucket[left : right + 1])
    return sorted(participating)


def evaluate_rule_over_events(rule: DetectionRule, events: list[Event]) -> list[str]:
    """Ids of events that satisfy `rule` across the supplied candidate set.

    Non-windowed rules reduce to a per-event filter. Windowed rules intersect
    the per-event filter with the set of events that participate in a
    satisfied threshold -- so a rule combining "severity is high" with
    "5 failures in 10 minutes per actor" only fires on events meeting both.
    """
    condition = rule.condition
    per_event = [e.id for e in events if evaluate_condition(condition, e)]
    windows = _collect_windows(condition)
    if not windows:
        return per_event

    allowed: set[str] = set(per_event)
    for leaf in windows:
        allowed &= set(_apply_window(leaf, events))
    return [eid for eid in per_event if eid in allowed]


def _scan_window_start(rule: DetectionRule) -> datetime:
    settings = get_settings()
    minutes = rule.evaluation_window_minutes or settings.detection_default_window_minutes
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _window_history_start(rule: DetectionRule) -> datetime:
    """How far back a threshold rule must look when triggered by a new batch.

    The widest `window.minutes` in the condition, doubled so a span that
    straddles the lookback boundary is still fully visible, and clamped to the
    rule's own evaluation window so a threshold rule never scans further than
    an explicit run would.
    """
    windows = _collect_windows(rule.condition)
    widest = max((int(w["window"]["minutes"]) for w in windows), default=0)
    lookback = timedelta(minutes=widest * 2)
    floor = _scan_window_start(rule)
    return max(datetime.now(timezone.utc) - lookback, floor)


def _already_matched(db: Session, *, tenant_id: str, rule_id: str, event_ids: list[str]) -> set[str]:
    if not event_ids:
        return set()
    rows = db.execute(
        select(RuleEventMatch.event_id).where(
            RuleEventMatch.tenant_id == tenant_id,
            RuleEventMatch.rule_id == rule_id,
            RuleEventMatch.event_id.in_(event_ids),
        )
    ).scalars()
    return set(rows)


def run_rule(
    db: Session,
    *,
    tenant_id: str,
    rule: DetectionRule,
    events: list[Event] | None = None,
) -> Alert | None:
    """Evaluate one rule and create an Alert for any not-yet-alerted matches.

    `events` is the candidate set. When None, a bounded window of the tenant's
    recent events is read through the telemetry store (never the whole
    corpus). When supplied -- the ingest-triggered path -- only the just-
    ingested batch is evaluated, which is what makes real-time detection cheap.

    Returns the new Alert, or None when nothing new matched.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    store = get_telemetry_store()

    if events is None:
        events = store.events_since(
            db,
            tenant_id=tenant_id,
            since=_scan_window_start(rule),
            limit=settings.detection_max_scan_events,
        )
        if len(events) == settings.detection_max_scan_events:
            logger.warning(
                "detection.scan_truncated",
                extra={
                    "tenant_id": tenant_id,
                    "rule_id": rule.id,
                    "limit": settings.detection_max_scan_events,
                },
            )
    elif _collect_windows(rule.condition):
        # A threshold rule cannot be judged from the incoming batch alone --
        # "5 failures in 10 minutes" needs the preceding 10 minutes of
        # history, which a freshly-ingested batch of 1 does not contain. Widen
        # the candidate set to the rule's window and union in the batch (the
        # batch may not be committed/visible to this read yet).
        history = store.events_since(
            db,
            tenant_id=tenant_id,
            since=_window_history_start(rule),
            limit=settings.detection_max_scan_events,
        )
        by_id = {e.id: e for e in history}
        by_id.update({e.id: e for e in events})
        events = list(by_id.values())

    rule.last_evaluated_at = now

    matched_ids = evaluate_rule_over_events(rule, events)
    if not matched_ids:
        return None

    already = _already_matched(db, tenant_id=tenant_id, rule_id=rule.id, event_ids=matched_ids)
    new_matches = [eid for eid in matched_ids if eid not in already]
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
        detection_source="rule",
    )
    db.add(alert)
    db.flush()

    for event_id in new_matches:
        db.add(
            RuleEventMatch(
                tenant_id=tenant_id,
                rule_id=rule.id,
                event_id=event_id,
                alert_id=alert.id,
                matched_at=now,
            )
        )
    try:
        db.flush()
    except IntegrityError:
        # A concurrent evaluator alerted on at least one of these events
        # first. Rolling back to a savepoint-free skip is correct: the other
        # worker's alert covers the overlap, and the next evaluation picks up
        # anything genuinely missed.
        db.rollback()
        logger.info(
            "detection.dedup_race_lost",
            extra={"tenant_id": tenant_id, "rule_id": rule.id, "events": len(new_matches)},
        )
        return None

    rule.last_matched_at = now
    rule.match_count = (rule.match_count or 0) + len(new_matches)
    db.flush()
    return alert


def run_all_rules(
    db: Session,
    *,
    tenant_id: str,
    events: list[Event] | None = None,
) -> list[Alert]:
    """Evaluate every enabled rule for a tenant.

    When `events` is supplied (ingest-triggered), all rules share that one
    candidate set -- a single pass over the batch rather than one bounded read
    per rule.
    """
    rules = list(
        db.execute(
            select(DetectionRule).where(
                DetectionRule.tenant_id == tenant_id,
                DetectionRule.is_enabled.is_(True),
            )
        ).scalars()
    )
    if not rules:
        return []

    shared_candidates = events
    if shared_candidates is None and len(rules) > 1:
        # One bounded read covering the widest window any rule asks for, so a
        # run-all is O(1) reads rather than O(rules).
        settings = get_settings()
        widest = max(r.evaluation_window_minutes or settings.detection_default_window_minutes for r in rules)
        shared_candidates = get_telemetry_store().events_since(
            db,
            tenant_id=tenant_id,
            since=datetime.now(timezone.utc) - timedelta(minutes=widest),
            limit=settings.detection_max_scan_events,
        )

    created: list[Alert] = []
    for rule in rules:
        candidates = shared_candidates
        if candidates is not None and events is None and rule.evaluation_window_minutes:
            # Narrow the shared read down to this rule's own window.
            cutoff = _scan_window_start(rule)
            candidates = [e for e in candidates if _occurred_at(e) >= cutoff]
        try:
            alert = run_rule(db, tenant_id=tenant_id, rule=rule, events=candidates)
        except ConditionError:
            # A malformed stored rule must not take down evaluation of every
            # other rule for the tenant.
            logger.exception("detection.rule_invalid", extra={"tenant_id": tenant_id, "rule_id": rule.id})
            continue
        if alert is not None:
            created.append(alert)
    return created

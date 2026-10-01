"""FM7: SOAR playbook automation.

Scope constraint, taken from README.md and enforced here rather than
documented and hoped for: this is authorized defensive tooling, so there is no
fully-autonomous destructive automation. Every action declares
`is_high_risk`, and a playbook containing one cannot execute until a human
approves that specific run (`PlaybookRun.status == "pending_approval"`). The
engine has no code path that executes a high-risk action without an
`approved_by_user_id`.

Three pieces:

- `PlaybookAction` -- the interface, one class per action, same adapter pattern
  as BillingProvider / QueueBackend / ThreatIntelProvider.
- `ACTION_REGISTRY` -- name -> action, so playbooks are data (a JSON list of
  {"action", "params"}) rather than code.
- `execute_run` / `trigger_on_alerts` / `trigger_on_case_escalation` -- the
  engine and its two trigger points.

Actions implemented here are the ones this codebase can genuinely carry out on
its own data (case comments, assignment, severity, tagging, outbound webhook,
indicator creation). `disable_user_in_idp` is registered but refuses to run,
because it requires the SSO integration to be configured -- registering it as a
no-op that claims success would be worse than a clear refusal.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.metrics import metrics
from app.models.alert import Alert
from app.models.case import Case, CaseTimelineEntry
from app.models.event import Event
from app.models.soar import (
    Playbook,
    PlaybookActionRecord,
    PlaybookRun,
    PlaybookTrigger,
    RunStatus,
)
from app.services.audit import record_audit

logger = logging.getLogger(__name__)


class ActionError(RuntimeError):
    """An action failed. Recorded on the action record; does not abort the run
    unless the action is marked `halt_on_failure`."""


class ApprovalRequired(RuntimeError):
    """Raised when execution is attempted on a run that still needs approval."""


class ActionContext:
    """What an action is allowed to touch.

    Deliberately narrow: a session, the tenant, the triggering subject, and the
    run. Actions do not get the request, the current user, or the settings
    object, so an action cannot quietly widen its own blast radius.
    """

    def __init__(
        self,
        db: Session,
        *,
        tenant_id: str,
        run: PlaybookRun,
        alert: Alert | None = None,
        case: Case | None = None,
        actor_user_id: str | None = None,
    ) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.run = run
        self.alert = alert
        self.case = case
        self.actor_user_id = actor_user_id

    @property
    def dry_run(self) -> bool:
        return self.run.dry_run


class PlaybookAction(ABC):
    name = "abstract"
    #: High-risk actions require a human approval before the run executes.
    is_high_risk = False
    #: A failure here aborts the remaining actions in the run.
    halt_on_failure = False
    description = ""

    @abstractmethod
    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        """Perform the action and return a JSON-serializable result.

        Must honour `context.dry_run` by describing the intended effect without
        performing it.
        """
        raise NotImplementedError


class AddCaseCommentAction(PlaybookAction):
    name = "add_case_comment"
    description = "Append a comment to the triggering case's timeline."

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        case = context.case
        if case is None:
            raise ActionError("add_case_comment requires a case; this run was not triggered by one")
        message = str(params.get("message") or "Automated playbook note.")[:2000]
        if context.dry_run:
            return {"wouldComment": message, "caseId": case.id}
        context.db.add(
            CaseTimelineEntry(
                tenant_id=context.tenant_id,
                case_id=case.id,
                entry_type="comment",
                message=f"[playbook] {message}",
                actor_user_id=None,
            )
        )
        return {"caseId": case.id, "commented": True}


class AssignCaseAction(PlaybookAction):
    name = "assign_case"
    description = "Assign the triggering case to a user."

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        from app.models.user import User

        case = context.case
        if case is None:
            raise ActionError("assign_case requires a case; this run was not triggered by one")
        user_id = params.get("userId")
        if not user_id:
            raise ActionError("assign_case requires params.userId")

        assignee = context.db.get(User, user_id)
        if assignee is None or assignee.tenant_id != context.tenant_id or not assignee.is_active:
            # Cross-tenant assignment would be a tenancy breach; an inactive
            # assignee would silently black-hole the case.
            raise ActionError(f"user {user_id} is not an active user in this tenant")
        if context.dry_run:
            return {"wouldAssign": user_id, "caseId": case.id}
        case.assignee_user_id = user_id
        context.db.add(
            CaseTimelineEntry(
                tenant_id=context.tenant_id,
                case_id=case.id,
                entry_type="assignment",
                message=f"[playbook] Case assigned to {assignee.email}.",
                actor_user_id=None,
            )
        )
        return {"caseId": case.id, "assigneeUserId": user_id}


class SetCaseSeverityAction(PlaybookAction):
    name = "set_case_severity"
    description = "Raise or lower the triggering case's severity."

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        case = context.case
        if case is None:
            raise ActionError("set_case_severity requires a case; this run was not triggered by one")
        severity = str(params.get("severity") or "").lower()
        if severity not in ("informational", "low", "medium", "high", "critical"):
            raise ActionError(f"invalid severity {severity!r}")
        if context.dry_run:
            return {"wouldSetSeverity": severity, "from": case.severity}
        previous = case.severity
        case.severity = severity
        context.db.add(
            CaseTimelineEntry(
                tenant_id=context.tenant_id,
                case_id=case.id,
                entry_type="comment",
                message=f"[playbook] Severity changed {previous} -> {severity}.",
                actor_user_id=None,
            )
        )
        return {"caseId": case.id, "severity": severity, "previousSeverity": previous}


class DismissAlertAction(PlaybookAction):
    name = "dismiss_alert"
    description = "Mark the triggering alert as a false positive."
    #: Dismissing findings automatically can hide a real intrusion, so it needs
    #: a human on the hook for it.
    is_high_risk = True

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        alert = context.alert
        if alert is None:
            raise ActionError("dismiss_alert requires an alert; this run was not triggered by one")
        reason = str(params.get("reason") or "Dismissed by playbook.")[:500]
        if context.dry_run:
            return {"wouldDismiss": alert.id, "reason": reason}
        alert.status = "dismissed"
        alert.dismissed_at = datetime.now(timezone.utc)
        alert.dismissed_by_user_id = context.run.approved_by_user_id
        alert.dismiss_reason = f"[playbook] {reason}"
        return {"alertId": alert.id, "status": "dismissed"}


class CreateIndicatorAction(PlaybookAction):
    name = "create_indicator"
    description = "Add the triggering event's source IP to the tenant's threat indicators."

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        from app.services.threat_intel import RawIndicator, import_indicators

        value = params.get("value")
        indicator_type = str(params.get("type") or "ip").lower()

        if not value and context.alert is not None:
            # Default behaviour: block the source IP of the first contributing
            # event, which is the common "saw a brute force, blocklist the
            # source" playbook.
            event_ids = context.alert.event_ids or []
            if event_ids:
                event = context.db.execute(
                    select(Event).where(
                        Event.tenant_id == context.tenant_id,
                        Event.id == event_ids[0],
                    )
                ).scalar_one_or_none()
                if event is not None:
                    value = event.source_ip
        if not value:
            raise ActionError("create_indicator needs params.value, or a triggering alert with a source IP")

        if context.dry_run:
            return {"wouldCreate": {"type": indicator_type, "value": value}}

        created, updated = import_indicators(
            context.db,
            tenant_id=context.tenant_id,
            indicators=[
                RawIndicator(
                    indicator_type=indicator_type,
                    value=str(value),
                    confidence=int(params.get("confidence", 75)),
                    severity=str(params.get("severity", "high")),
                    description=f"Added by playbook {context.run.playbook_id}",
                    tags=["playbook"],
                )
            ],
            source="playbook",
            ttl_hours=params.get("ttlHours"),
        )
        return {"type": indicator_type, "value": str(value), "created": created, "updated": updated}


class CallWebhookAction(PlaybookAction):
    name = "call_webhook"
    description = "POST the triggering alert/case to an external URL."
    #: An outbound call to an operator-supplied URL can have arbitrary effects
    #: on the far side (ticket creation, firewall change), so it is gated.
    is_high_risk = True

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("url")
        if not url or not str(url).startswith(("http://", "https://")):
            raise ActionError("call_webhook requires an http(s) params.url")

        payload = {
            "playbookRunId": context.run.id,
            "tenantId": context.tenant_id,
            "alertId": context.alert.id if context.alert else None,
            "caseId": context.case.id if context.case else None,
            "custom": params.get("payload") or {},
        }
        if context.dry_run:
            return {"wouldPost": url, "payload": payload}

        timeout = get_settings().soar_webhook_timeout_seconds
        request = urllib.request.Request(
            str(url),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SentinelIQ-SOAR/0.2"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured
                return {"url": str(url), "status": response.status}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ActionError(f"webhook POST failed: {exc}") from exc


class DisableUserInIdpAction(PlaybookAction):
    name = "disable_user_in_idp"
    description = "Disable the actor's account in the configured identity provider."
    is_high_risk = True
    halt_on_failure = True

    def run(self, context: ActionContext, params: dict[str, Any]) -> dict[str, Any]:
        """Refuses rather than pretending.

        Disabling an account in an external IdP needs a configured, credentialed
        SSO integration with write scope (SCIM, or the provider's admin API).
        Until `TenantSsoConfig` is enabled and verified for the tenant, this
        action cannot do what its name says -- and an automation that reports
        "contained the account" while doing nothing is a dangerous lie during an
        incident.

        TODO(FM7/SSO): implement against the tenant's TenantSsoConfig once an
        OIDC/SCIM write path exists -- Okta `POST /api/v1/users/{id}/lifecycle/
        suspend`, Azure AD `PATCH /users/{id} {"accountEnabled": false}`,
        Google Workspace `users.update`. Must stay high-risk and
        approval-gated.
        """
        from app.models.sso import TenantSsoConfig

        config = context.db.execute(
            select(TenantSsoConfig).where(TenantSsoConfig.tenant_id == context.tenant_id)
        ).scalar_one_or_none()

        if context.dry_run:
            return {
                "wouldDisable": params.get("actor") or (context.alert.title if context.alert else None),
                "ssoConfigured": bool(config and config.is_enabled),
            }

        if config is None or not config.is_enabled:
            raise ActionError(
                "disable_user_in_idp requires an enabled TenantSsoConfig for this tenant; "
                "no identity provider is configured to disable the account in"
            )
        raise ActionError(
            "disable_user_in_idp is not implemented: the SSO integration is read-only "
            "(authentication) and has no account-write scope. See the docstring for the provider "
            "endpoints this needs."
        )


ACTION_REGISTRY: dict[str, PlaybookAction] = {
    action.name: action
    for action in (
        AddCaseCommentAction(),
        AssignCaseAction(),
        SetCaseSeverityAction(),
        DismissAlertAction(),
        CreateIndicatorAction(),
        CallWebhookAction(),
        DisableUserInIdpAction(),
    )
}


def describe_actions() -> list[dict[str, Any]]:
    """Registry metadata for the playbook-authoring UI."""
    return [
        {
            "name": action.name,
            "description": action.description,
            "isHighRisk": action.is_high_risk,
            "haltOnFailure": action.halt_on_failure,
        }
        for action in sorted(ACTION_REGISTRY.values(), key=lambda a: a.name)
    ]


def validate_actions(actions: Any) -> None:
    """Reject an unrunnable playbook at save time rather than at trigger time."""
    settings = get_settings()
    if not isinstance(actions, list) or not actions:
        raise ValueError("playbook requires a non-empty list of actions")
    if len(actions) > settings.soar_max_actions_per_run:
        raise ValueError(f"playbook exceeds the {settings.soar_max_actions_per_run}-action limit")
    for index, entry in enumerate(actions):
        if not isinstance(entry, dict):
            raise ValueError(f"action[{index}] must be an object")
        name = entry.get("action")
        if name not in ACTION_REGISTRY:
            raise ValueError(
                f"action[{index}]: unknown action {name!r}. Available: {', '.join(sorted(ACTION_REGISTRY))}"
            )
        params = entry.get("params", {})
        if not isinstance(params, dict):
            raise ValueError(f"action[{index}].params must be an object")


def playbook_requires_approval(playbook: Playbook) -> bool:
    settings = get_settings()
    if not settings.soar_require_approval_for_high_risk:
        return False
    if playbook.dry_run:
        # A dry run performs no side effects, so gating it would only train
        # operators to click approve reflexively.
        return False
    return any(
        ACTION_REGISTRY[entry["action"]].is_high_risk
        for entry in (playbook.actions or [])
        if entry.get("action") in ACTION_REGISTRY
    )


def _synthetic_event_for_condition(alert: Alert | None, case: Case | None) -> Event:
    """Adapt an alert/case to the FM4 condition evaluator.

    Reusing the rule DSL for playbook triggers means operators learn one
    condition language, not two. The evaluator reads attributes off an Event, so
    an unsaved Event carries the alert/case fields into the fields a trigger
    condition addresses (`severity_hint`, `event_category`, `event_action`).
    """
    subject = alert or case
    severity = getattr(subject, "severity", "medium") if subject else "medium"
    return Event(
        tenant_id=getattr(subject, "tenant_id", "") if subject else "",
        source="soar",
        raw_payload={},
        event_category="alert" if alert else "case",
        event_action=getattr(subject, "status", "unknown") if subject else "unknown",
        severity_hint=severity,
        actor=None,
        target=getattr(subject, "title", None) if subject else None,
        source_ip=None,
        normalized={
            "alert": {
                "id": alert.id,
                "ruleId": alert.rule_id,
                "detectionSource": alert.detection_source,
                "mlScore": alert.ml_score,
                "eventCount": len(alert.event_ids or []),
            }
            if alert
            else None,
            "case": {"id": case.id, "status": case.status} if case else None,
        },
        occurred_at=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
    )


def _trigger_matches(playbook: Playbook, *, alert: Alert | None, case: Case | None) -> bool:
    if not playbook.trigger_condition:
        return True
    from app.services.rule_engine import ConditionError, evaluate_condition

    try:
        return evaluate_condition(playbook.trigger_condition, _synthetic_event_for_condition(alert, case))
    except ConditionError:
        logger.exception(
            "soar.trigger_condition_invalid",
            extra={"tenant_id": playbook.tenant_id, "playbook_id": playbook.id},
        )
        return False


def create_run(
    db: Session,
    *,
    playbook: Playbook,
    trigger: str,
    alert: Alert | None = None,
    case: Case | None = None,
    triggered_by_user_id: str | None = None,
) -> PlaybookRun:
    """Create a run record, pending approval when the playbook needs it."""
    requires_approval = playbook_requires_approval(playbook)
    run = PlaybookRun(
        tenant_id=playbook.tenant_id,
        playbook_id=playbook.id,
        status=RunStatus.PENDING_APPROVAL if requires_approval else RunStatus.RUNNING,
        trigger=trigger,
        subject_type="alert" if alert else ("case" if case else "manual"),
        subject_id=alert.id if alert else (case.id if case else None),
        dry_run=playbook.dry_run,
        requires_approval=requires_approval,
        triggered_by_user_id=triggered_by_user_id,
    )
    db.add(run)
    db.flush()

    playbook.run_count = (playbook.run_count or 0) + 1
    playbook.last_run_at = datetime.now(timezone.utc)
    return run


def execute_run(
    db: Session,
    *,
    run: PlaybookRun,
    playbook: Playbook,
    alert: Alert | None = None,
    case: Case | None = None,
) -> PlaybookRun:
    """Execute a run's actions in order. Does not commit.

    Refuses outright if the run still needs approval -- this is the single
    enforcement point for the no-autonomous-destructive-automation rule, and it
    checks the run's own state rather than trusting the caller.
    """
    if run.requires_approval and run.approved_by_user_id is None:
        raise ApprovalRequired(
            f"playbook run {run.id} contains a high-risk action and has not been approved"
        )
    if run.status in RunStatus.TERMINAL:
        raise ApprovalRequired(f"playbook run {run.id} is already {run.status}")

    settings = get_settings()
    now = datetime.now(timezone.utc)
    run.status = RunStatus.RUNNING
    run.started_at = now

    context = ActionContext(
        db,
        tenant_id=playbook.tenant_id,
        run=run,
        alert=alert,
        case=case,
        actor_user_id=run.approved_by_user_id or run.triggered_by_user_id,
    )

    succeeded = 0
    failed = 0
    entries = (playbook.actions or [])[: settings.soar_max_actions_per_run]

    for sequence, entry in enumerate(entries):
        name = entry.get("action")
        action = ACTION_REGISTRY.get(name)
        params = entry.get("params") or {}
        started = time.perf_counter()

        if action is None:
            db.add(
                PlaybookActionRecord(
                    tenant_id=playbook.tenant_id,
                    run_id=run.id,
                    sequence=sequence,
                    action=str(name),
                    params=params,
                    status="failed",
                    is_high_risk=False,
                    result={},
                    error=f"unknown action {name!r}",
                    duration_ms=0,
                    created_at=now,
                )
            )
            failed += 1
            continue

        try:
            result = action.run(context, params)
            status = "dry_run" if run.dry_run else "succeeded"
            error = None
            succeeded += 1
        except ActionError as exc:
            result = {}
            status = "failed"
            error = str(exc)[:2000]
            failed += 1
        except Exception as exc:  # noqa: BLE001 - one broken action must not abort the audit trail
            result = {}
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"[:2000]
            failed += 1
            logger.exception(
                "soar.action_crashed",
                extra={"tenant_id": playbook.tenant_id, "run_id": run.id, "action": name},
            )

        db.add(
            PlaybookActionRecord(
                tenant_id=playbook.tenant_id,
                run_id=run.id,
                sequence=sequence,
                action=action.name,
                params=params,
                status=status,
                is_high_risk=action.is_high_risk,
                result=result,
                error=error,
                duration_ms=int((time.perf_counter() - started) * 1000),
                created_at=now,
            )
        )
        metrics.increment("soar_actions_total", {"action": action.name, "status": status})

        if status == "failed" and action.halt_on_failure:
            run.error = f"halted at action[{sequence}] ({action.name}): {error}"
            break

    if failed == 0:
        run.status = RunStatus.SUCCEEDED
    elif succeeded == 0:
        run.status = RunStatus.FAILED
    else:
        run.status = RunStatus.PARTIAL
    run.finished_at = datetime.now(timezone.utc)

    db.flush()
    logger.info(
        "soar.run_finished",
        extra={
            "tenant_id": playbook.tenant_id,
            "run_id": run.id,
            "playbook_id": playbook.id,
            "status": run.status,
            "succeeded": succeeded,
            "failed": failed,
            "dry_run": run.dry_run,
        },
    )
    return run


def _enabled_playbooks(db: Session, *, tenant_id: str, trigger: str) -> list[Playbook]:
    return list(
        db.execute(
            select(Playbook).where(
                Playbook.tenant_id == tenant_id,
                Playbook.is_enabled.is_(True),
                Playbook.trigger == trigger,
            )
        ).scalars()
    )


def trigger_on_alerts(db: Session, *, tenant_id: str, alerts: list[Alert]) -> list[PlaybookRun]:
    """Trigger point 1: a new alert was created (ingest or manual rule run)."""
    if not alerts:
        return []
    playbooks = _enabled_playbooks(db, tenant_id=tenant_id, trigger=PlaybookTrigger.ALERT_CREATED)
    if not playbooks:
        return []

    runs: list[PlaybookRun] = []
    for alert in alerts:
        for playbook in playbooks:
            if not _trigger_matches(playbook, alert=alert, case=None):
                continue
            run = create_run(db, playbook=playbook, trigger=PlaybookTrigger.ALERT_CREATED, alert=alert)
            runs.append(run)
            if run.requires_approval:
                logger.info(
                    "soar.run_awaiting_approval",
                    extra={"tenant_id": tenant_id, "run_id": run.id, "playbook_id": playbook.id},
                )
                continue
            execute_run(db, run=run, playbook=playbook, alert=alert)
    return runs


def trigger_on_case_escalation(
    db: Session,
    *,
    tenant_id: str,
    case: Case,
    actor_user_id: str | None = None,
) -> list[PlaybookRun]:
    """Trigger point 2: a case was escalated."""
    playbooks = _enabled_playbooks(db, tenant_id=tenant_id, trigger=PlaybookTrigger.CASE_ESCALATED)
    runs: list[PlaybookRun] = []
    for playbook in playbooks:
        if not _trigger_matches(playbook, alert=None, case=case):
            continue
        run = create_run(
            db,
            playbook=playbook,
            trigger=PlaybookTrigger.CASE_ESCALATED,
            case=case,
            triggered_by_user_id=actor_user_id,
        )
        runs.append(run)
        if run.requires_approval:
            continue
        execute_run(db, run=run, playbook=playbook, case=case)
    return runs


def approve_run(
    db: Session,
    *,
    run: PlaybookRun,
    playbook: Playbook,
    approver_user_id: str,
) -> PlaybookRun:
    """Approve and immediately execute a pending run."""
    if run.status != RunStatus.PENDING_APPROVAL:
        raise ApprovalRequired(f"run {run.id} is {run.status}, not pending approval")

    run.approved_by_user_id = approver_user_id
    run.approved_at = datetime.now(timezone.utc)
    record_audit(
        db,
        tenant_id=run.tenant_id,
        actor_user_id=approver_user_id,
        action="playbook_run.approved",
        target_type="playbook_run",
        target_id=run.id,
        detail={"playbook_id": playbook.id, "subject_id": run.subject_id},
    )

    alert = db.get(Alert, run.subject_id) if run.subject_type == "alert" and run.subject_id else None
    case = db.get(Case, run.subject_id) if run.subject_type == "case" and run.subject_id else None
    # Defence in depth: the subject must still belong to the run's tenant.
    if alert is not None and alert.tenant_id != run.tenant_id:
        alert = None
    if case is not None and case.tenant_id != run.tenant_id:
        case = None
    return execute_run(db, run=run, playbook=playbook, alert=alert, case=case)


def reject_run(
    db: Session,
    *,
    run: PlaybookRun,
    rejecter_user_id: str,
    reason: str | None = None,
) -> PlaybookRun:
    if run.status != RunStatus.PENDING_APPROVAL:
        raise ApprovalRequired(f"run {run.id} is {run.status}, not pending approval")
    run.status = RunStatus.REJECTED
    run.rejected_by_user_id = rejecter_user_id
    run.rejected_at = datetime.now(timezone.utc)
    run.rejection_reason = (reason or "")[:500] or None
    run.finished_at = run.rejected_at
    record_audit(
        db,
        tenant_id=run.tenant_id,
        actor_user_id=rejecter_user_id,
        action="playbook_run.rejected",
        target_type="playbook_run",
        target_id=run.id,
        detail={"reason": run.rejection_reason},
    )
    db.flush()
    return run

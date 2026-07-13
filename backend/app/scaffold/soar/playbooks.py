"""SCAFFOLD ONLY -- FM7 SOAR playbook automation.

Owner (per docs/TEAM.md): shared between [3] Backend/Cloud/AI Systems
Engineer (Security Architect) and [4] AI/ML & Automation Engineer +
Analytics.

TODO(FM7): Playbook entity (defines a trigger condition + ordered list of
actions) and PlaybookRun entity (execution record / audit trail).

TODO(FM7): action registry -- pluggable actions such as "add case timeline
comment", "assign case", "call outbound webhook", "disable user in IdP"
(future SSO integration point, see app/scaffold/sso/), each implementing a
small `PlaybookAction` interface analogous to BillingProvider /
QueueBackend elsewhere in this repo.

TODO(FM7): trigger playbooks from app/services/rule_engine.py::run_rule
(on new Alert) and from app/api/v1/cases.py status transitions (on
escalation), with per-tenant enable/disable and a dry-run mode.

TODO(FM7): human-in-the-loop approval step for any destructive/high-risk
action, consistent with this platform's authorized-defensive-tooling scope
(see README.md) -- no fully-autonomous destructive automation.
"""

# Intentionally no logic yet. See module docstring for scope.

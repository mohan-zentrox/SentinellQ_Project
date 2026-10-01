# API Conventions & Reference

- **Style**: REST over HTTPS, documented with OpenAPI 3.1 (FastAPI
  auto-generates this at `/openapi.json`, human-friendly docs at `/docs`).
- **JSON casing**: request and response bodies use **camelCase** keys.
  Internally the backend is snake_case Python; `app/schemas/common.py`'s
  `CamelModel` base class handles the conversion both ways.
- **URLs**: kebab-case resource names, e.g. `/v1/detection-rules`,
  `/v1/threat-indicators`, `/v1/playbook-runs`.
- **Entity IDs**: every ID is a prefixed string (never a bare UUID/int). See
  `backend/app/core/ids.py` for the full map.
- **Auth**:
  - `Authorization: Bearer <access JWT>` for human/analyst callers.
  - `X-Service-Token: <token>` for machine ingestion (`POST /v1/events/ingest`).
  - `?token=<signed>` for report downloads (see FM9 below).
  - Provider webhooks are authenticated by signature, not by session.
- **Pagination**: `page` / `pageSize` query params; responses include `total`,
  `page`, `pageSize`, `items`.
- **Errors**: standard HTTP status codes. `401` (missing/invalid/revoked auth),
  `403` (RBAC denial), `404` (not found *or* not in the caller's tenant --
  cross-tenant reads intentionally look identical to "not found"), `409`
  (invalid state transition, e.g. a case status change or dismissing a promoted
  alert), `422` (validation, including an invalid rule condition), `429` (FM10
  quota exceeded, or login rate limited -- carries `Retry-After`).
- **Request tracing**: every response carries `X-Request-Id`. Supply your own and
  it is echoed, so a trace survives the hop through the nginx proxy.

## Sessions

An access token is a short-lived stateless JWT. A refresh token is opaque,
stored hashed, **single-use**, and revocable.

- `POST /v1/auth/refresh` rotates: the presented token is consumed and a new pair
  is issued.
- Presenting an already-used refresh token is treated as theft and revokes the
  **entire session family**. A 401 from this endpoint can therefore mean "stale
  token" or "your session was just revoked because someone replayed it".
- A password change, an admin password reset, a user deactivation, or
  `logout` with `allDevices: true` bumps the user's token version, which
  invalidates every access token already issued -- not just the refresh tokens.
- Clients should issue **one** refresh for concurrent 401s. Firing several looks
  like replay and will revoke the session (see
  `frontend/src/api/client.ts` for a correct implementation).

## Endpoint summary

102 routes. `analyst+`, `admin+`, `owner` denote the minimum role; privilege is
ordered, so an owner satisfies `admin+`.

### Meta (unauthenticated)

| Method & path | Notes |
|---|---|
| `GET /health` | Liveness. Is the process up? (What the container healthcheck polls.) |
| `GET /readiness` | Readiness. Can it serve traffic -- i.e. is the database reachable? `503` when not. |
| `GET /metrics` | Prometheus text format. Aggregate request counts/latencies; no tenant labels, no telemetry contents. |

### FM1 -- Auth & sessions

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/auth/signup` | none | Creates Tenant + Owner user, returns access + refresh tokens |
| `POST /v1/auth/login` | none | Rate limited per (email, IP); one message for every failure mode so it cannot be used to enumerate accounts |
| `POST /v1/auth/refresh` | refresh token | Single-use rotation |
| `POST /v1/auth/logout` | JWT | `refreshToken` ends one session; `allDevices: true` ends all and invalidates issued access tokens |
| `GET /v1/auth/sessions` | JWT | The caller's own active sessions only |
| `POST /v1/auth/change-password` | JWT | Requires the current password; ends every session |
| `GET /v1/auth/me` | JWT | Current user |

### FM1/FM11 -- Tenant, users, ingestion credentials

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/tenants/me` | JWT | Current tenant |
| `PATCH /v1/tenants/me` | owner | Rename |
| `GET /v1/tenants/me/users` | admin+ | Tenant-scoped roster |
| `POST /v1/tenants/me/users` | admin+ | Only an owner may grant the owner role |
| `PATCH /v1/tenants/me/users/{id}` | admin+ | Role / name / active. Refuses self-role-change, self-deactivation, and demoting the last active owner |
| `POST /v1/tenants/me/users/{id}/reset-password` | admin+ | Ends the target's sessions. An admin cannot reset an owner's password |
| `GET /v1/tenants/me/service-tokens` | admin+ | Never returns token material |
| `POST /v1/tenants/me/service-tokens` | admin+ | Plaintext returned **once**; only a hash is stored |
| `DELETE /v1/tenants/me/service-tokens/{id}` | admin+ | Revokes (deactivates, retains for audit) |

### FM2/FM3 -- Ingestion & telemetry

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/events/ingest` | service token | Accepts a batch (1-500). Normalizes, stores, enriches, detects, notifies, automates, meters. `202` |
| `GET /v1/events` | JWT | Paginated; filters: `severity`, `eventCategory`, `eventAction`, `actor`, `sourceIp`, `source`, `occurredAfter`, `occurredBefore`, `search` |
| `GET /v1/events/{id}` | JWT | Adds the raw and normalized documents plus enrichment |

**Ingest response semantics.** A `202` means *accepted*, not *stored*. Read
`processing`:

- `"synchronous"` -- the batch was normalized, stored and evaluated during the
  request; `eventIds` is populated and `alertsCreated` is meaningful.
- `"queued"` -- the batch was enqueued for the worker; `eventIds` is empty.
  Without a worker running, nothing will store it.

### FM4 -- Detection rules

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/detection-rules` | analyst+ | Condition validated at create time (`422` with the reason) |
| `GET /v1/detection-rules` | JWT | Optional `enabled` filter |
| `GET /v1/detection-rules/{id}` | JWT | Includes `matchCount`, `lastMatchedAt`, `lastEvaluatedAt` |
| `PATCH /v1/detection-rules/{id}` | analyst+ | Partial; omitted fields are untouched |
| `DELETE /v1/detection-rules/{id}` | admin+ | Deletes the rule and its dedup ledger. **Alerts it raised are kept** -- they are findings an analyst may be working |
| `POST /v1/detection-rules/test` | analyst+ | Dry run against recent events. Creates nothing |
| `POST /v1/detection-rules/{id}/run` | analyst+ | Evaluate one rule over a bounded window |
| `POST /v1/detection-rules/run-all` | analyst+ | Evaluate all enabled rules. A malformed stored rule is skipped, not fatal |

### FM4/FM6 -- Alerts

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/alerts` | JWT | Filters: `status`, `severity`, `detectionSource`, `ruleId` |
| `GET /v1/alerts/{id}` | JWT | Inlines the contributing events and their enrichment |
| `PATCH /v1/alerts/{id}` | analyst+ | Triage: `dismissed` (with a reason) or `open`. `409` on a promoted alert |
| `PATCH /v1/alerts` | analyst+ | Bulk triage, up to 500. Promoted alerts are skipped, not fatal |
| `POST /v1/alerts/promote` | analyst+ | Promote alert(s) into a Case. `409` if any is already promoted |

### FM6 -- Cases

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/cases` | analyst+ | Any supplied `alertIds` must belong to the caller's tenant |
| `GET /v1/cases` | JWT | Filters: `status`, `severity`, `assigneeUserId`, `unassigned` |
| `GET /v1/cases/{id}` | JWT | |
| `PATCH /v1/cases/{id}` | analyst+ | Title / description / severity |
| `GET /v1/cases/{id}/timeline` | JWT | Append-only audit trail |
| `POST /v1/cases/{id}/comments` | analyst+ | Analyst note on the timeline |
| `PATCH /v1/cases/{id}/status` | analyst+ | State machine (`409` if invalid). Optional `note`. Escalation is an FM7 trigger |
| `PATCH /v1/cases/{id}/assign` | analyst+ | Assignee must be an active user in the tenant; `null` unassigns |

### FM5 -- Threat intelligence

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/threat-indicators` | JWT | Filters: `indicatorType`, `source`, `activeOnly`, `search` |
| `POST /v1/threat-indicators` | analyst+ | Upserts; re-adding never lowers confidence |
| `POST /v1/threat-indicators/bulk` | analyst+ | Up to 1000 |
| `GET /v1/threat-indicators/{id}` | JWT | |
| `PATCH /v1/threat-indicators/{id}` | analyst+ | |
| `DELETE /v1/threat-indicators/{id}` | analyst+ | Deactivates, retaining it so historical alerts stay explainable |
| `POST /v1/threat-indicators/expire-stale` | admin+ | Staleness sweep |
| `GET /v1/threat-indicators/stats/summary` | JWT | Inventory and match rate (the data-QA view) |
| `GET /v1/threat-indicators/preview/{type}/{value}` | JWT | What enrichment would annotate. Use this to confirm a new indicator is actually matchable |
| `GET /v1/threat-feeds` | analyst+ | |
| `POST /v1/threat-feeds` | admin+ | Credentials are named via `apiKeyEnvVar`, never stored |
| `PATCH /v1/threat-feeds/{id}` | admin+ | |
| `DELETE /v1/threat-feeds/{id}` | admin+ | Imported indicators are left to expire on their TTL |
| `POST /v1/threat-feeds/{id}/refresh` | analyst+ | Returns `200` with the outcome **even on failure** -- a down feed is operational news, not a server error |
| `POST /v1/threat-feeds/refresh-all` | analyst+ | |

### FM7 -- SOAR

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/playbook-actions` | JWT | The action registry with `isHighRisk` flags |
| `GET /v1/playbooks` | JWT | `requiresApproval` is computed from the actions |
| `POST /v1/playbooks` | admin+ | Actions and trigger condition validated at save time |
| `GET /v1/playbooks/{id}` | JWT | |
| `PATCH /v1/playbooks/{id}` | admin+ | Includes toggling `isEnabled` / `dryRun` |
| `DELETE /v1/playbooks/{id}` | admin+ | Run history is retained as an automation audit trail |
| `POST /v1/playbooks/{id}/run` | analyst+ | Manual trigger. `201` with `pending_approval` when high-risk |
| `GET /v1/playbook-runs` | JWT | Filters: `status`, `playbookId` |
| `GET /v1/playbook-runs/{id}` | JWT | Per-action outcomes |
| `POST /v1/playbook-runs/{id}/approve` | admin+ | Approves **and executes**. The approver is recorded |
| `POST /v1/playbook-runs/{id}/reject` | admin+ | Nothing executes |

### FM8 -- Analytics

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/analytics/kpis` | JWT | Volume, dismissals, false-positive rate, MTTD, MTTR, case counts, breakdowns |
| `GET /v1/analytics/alerts/timeseries` | JWT | Bucketed volume for the trend chart |
| `GET /v1/analytics/detection-coverage` | JWT | Which rules fire, and which never have |
| `GET /v1/analytics/ingestion` | JWT | Volume by source and severity; enriched count |

### FM9 -- Compliance reports

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/reports/templates` | JWT | `alert_summary`, `case_summary`, `control_evidence` |
| `GET /v1/reports` | JWT | Ready reports carry a signed `downloadUrl` and its expiry |
| `POST /v1/reports` | analyst+ | Formats: `csv`, `json`, `html` |
| `GET /v1/reports/{id}` | JWT | |
| `DELETE /v1/reports/{id}` | admin+ | Removes the artifact too |
| `GET /v1/reports/{id}/download?token=` | signed token | Deliberately not session-authenticated, so a browser download works. The token binds report id + tenant id + expiry; a bad or expired one returns `404`, because the existence of a report id is itself tenant information |

### FM10 -- Billing

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/billing/plans` | none | Plan catalog |
| `POST /v1/billing/checkout` | owner | Creates a session. **Does not** move the tenant's quota yet |
| `POST /v1/billing/webhook/checkout-completed` | owner | Dev-only completion for the mocked provider. Refuses with `409` when a real provider is configured |
| `POST /v1/billing/webhook/stripe` | signature | Real HMAC verification (`t=`/`v1=`, constant-time, 5-minute replay tolerance). Handles `checkout.session.completed` and `customer.subscription.deleted` |
| `GET /v1/billing/subscription` | analyst+ | |
| `POST /v1/billing/subscription/cancel` | owner | Cancel at period end by default; `immediate: true` downgrades now |
| `GET /v1/billing/usage` | analyst+ | Current period vs. quota, plus `overQuota` |
| `GET /v1/billing/usage/history` | analyst+ | Per-period, newest first |

### FM11 -- Administration

| Method & path | Auth | Notes |
|---|---|---|
| `GET /v1/admin/audit-log` | admin+ | Filters: `action` (prefix), `actorUserId`, `days`. Sensitive values are redacted at write time |
| `GET /v1/admin/notifications` | admin+ | Delivery records -- "was the on-call actually paged?" |
| `GET /v1/admin/ml-models` | admin+ | Versions. Learned parameters are deliberately omitted |
| `GET /v1/admin/ml-models/active` | admin+ | |
| `POST /v1/admin/ml-models/train` | admin+ | `trained: false` with a reason when there is too little history -- an expected state, not an error |
| `PATCH /v1/admin/ml-models/{id}` | admin+ | Activate (rollback) or adjust the threshold |
| `GET /v1/admin/sso` | owner | |
| `PUT /v1/admin/sso` | owner | `ssoRequired` is refused unless the config is enabled **and verified**, so a tenant cannot lock itself out |
| `POST /v1/admin/sso/verify` | owner | Checks the issuer's OIDC discovery document |
| `DELETE /v1/admin/sso` | owner | |
| `GET /v1/admin/settings` | admin+ | Which adapters this deployment resolved. Non-secret selectors and booleans only |

## Detection rule condition DSL (FM4)

```json
{"field": "severity_hint", "op": "eq", "value": "critical"}
```

Composable via `all` (AND), `any` (OR) and `not`:

```json
{
  "all": [
    {"field": "actor", "op": "regex", "value": "^svc-"},
    {"not": {"field": "source_ip", "op": "cidr", "value": "10.0.0.0/8"}}
  ]
}
```

**Operators**: `eq`, `neq`, `contains`, `icontains`, `in`, `not_in`, `gt`, `gte`,
`lt`, `lte`, `regex`, `exists`, `cidr`.

**Fields** resolve in this order: the normalized event's flat attributes
(`event_category`, `event_action`, `severity_hint`, `actor`, `target`,
`source_ip`, `source`), then a dotted path into `normalized.*`, then
`enrichment.*` -- which makes FM5 threat intel rule-addressable:

```json
{"field": "enrichment.maxConfidence", "op": "gte", "value": 80}
{"field": "enrichment.tags", "op": "contains", "value": "ransomware"}
```

**Time-window thresholds.** A leaf may carry a `window`, turning it from a
per-event predicate into a threshold over time:

```json
{
  "field": "event_action", "op": "eq", "value": "login_failed",
  "window": {"minutes": 10, "count": 5, "groupBy": "actor"}
}
```

reads as "5+ matching events within any 10-minute span, grouped by actor".
`count` must be >= 2, and a windowed leaf cannot be nested under `not` (negating
a threshold is ambiguous) -- both rejected at save time with a `422`.

Ordered comparisons coerce across the JSON type boundary, so a rule authored with
`80` still matches enrichment holding `"80"`. Returning false on a type mismatch
is the failure mode that makes a rule quietly stop firing.

**Dedup**: `rule_event_matches` is the authority for "already alerted on this
(rule, event)". Its unique constraint also makes concurrent workers safe.

## Case status state machine (FM6)

```
new -> investigating -> resolved
                      -> escalated -> investigating
                                   -> resolved
```

`resolved` is terminal. Any transition not shown returns `409`. Escalation also
fires FM7 playbooks bound to `case_escalated`.

## SOAR action registry (FM7)

| Action | High risk | Effect |
|---|---|---|
| `add_case_comment` | no | Appends to the case timeline |
| `assign_case` | no | Assignee must be an active user in the tenant |
| `set_case_severity` | no | Raises or lowers severity |
| `create_indicator` | no | Adds the triggering event's source IP to the tenant's intel |
| `dismiss_alert` | **yes** | Automated dismissal can hide a real intrusion |
| `call_webhook` | **yes** | Arbitrary effects on the far side |
| `disable_user_in_idp` | **yes** | Refuses: needs an IdP integration with account-write scope |

A playbook containing any high-risk action creates every run in
`pending_approval`, and the engine has no path that executes one without an
`approvedByUserId`. Setting `dryRun` exempts a playbook from the gate, because a
dry run performs nothing to approve.

# API Conventions & Reference

- **Style**: REST over HTTPS, documented with OpenAPI 3.1 (FastAPI
  auto-generates this at `/openapi.json`, human-friendly docs at `/docs`
  when the backend is running).
- **JSON casing**: request and response bodies use **camelCase** keys.
  Internally the backend is snake_case Python; `app/schemas/common.py`'s
  `CamelModel` base class handles the conversion both ways.
- **URLs**: kebab-case resource names, e.g. `/v1/detection-rules`.
- **Entity IDs**: every ID is a prefixed string (never a bare UUID/int):
  `ten_`, `usr_`, `evt_`, `alrt_`, `case_`, `rule_`, `plan_`, `sub_`,
  `svct_`, `tl_`, `usage_`. See `backend/app/core/ids.py`.
- **Auth**: `Authorization: Bearer <JWT>` for human/analyst callers;
  `X-Service-Token: <token>` for machine ingestion callers
  (`POST /v1/events/ingest`).
- **Pagination**: `page` / `pageSize` query params; responses include
  `total`, `page`, `pageSize`, `items`.
- **Errors**: standard HTTP status codes. `401` (missing/invalid auth),
  `403` (RBAC denial), `404` (not found / not in caller's tenant --
  cross-tenant reads intentionally look identical to "not found"), `409`
  (e.g. invalid case status transition), `422` (validation), `429` (FM10
  quota exceeded).

## Endpoint summary

| Method & path | Auth | Notes |
|---|---|---|
| `POST /v1/auth/signup` | none | FM1: creates Tenant + Owner user, returns JWT |
| `POST /v1/auth/login` | none | Returns JWT |
| `GET /v1/auth/me` | JWT | Current user |
| `GET /v1/tenants/me` | JWT | Current tenant |
| `GET /v1/tenants/me/users` | JWT (admin+) | Tenant-scoped user list |
| `POST /v1/tenants/me/users` | JWT (admin+) | Create a user with a role |
| `POST /v1/tenants/me/service-tokens` | JWT (admin+) | Issue an ingestion credential |
| `POST /v1/events/ingest` | service token | FM2/FM3: accepts a batch, normalizes, stores, meters usage, 429s over quota |
| `GET /v1/events` | JWT | FM3: paginated, tenant-scoped |
| `POST /v1/detection-rules` | JWT (analyst+) | FM4: create a rule with a JSON condition |
| `GET /v1/detection-rules` / `/{id}` | JWT | List/read rules |
| `POST /v1/detection-rules/{id}/run` | JWT (analyst+) | Evaluate one rule, create Alert(s) |
| `POST /v1/detection-rules/run-all` | JWT (analyst+) | Evaluate all enabled rules |
| `GET /v1/alerts` / `/{id}` | JWT | FM4/FM6: list/read alerts |
| `POST /v1/alerts/promote` | JWT (analyst+) | FM6: promote alert(s) into a Case |
| `POST /v1/cases` | JWT (analyst+) | FM6: create a case directly |
| `GET /v1/cases` / `/{id}` | JWT | List/read cases |
| `GET /v1/cases/{id}/timeline` | JWT | Case audit trail |
| `PATCH /v1/cases/{id}/status` | JWT (analyst+) | State machine transition (409 if invalid) |
| `PATCH /v1/cases/{id}/assign` | JWT (analyst+) | Assign a case owner |
| `GET /v1/billing/plans` | none | Plan catalog |
| `POST /v1/billing/checkout` | JWT (owner) | FM10: mocked Stripe Checkout session |
| `POST /v1/billing/webhook/checkout-completed` | JWT (owner) | Simulated Stripe webhook (dev/test only) |
| `GET /v1/billing/subscription` | JWT (analyst+) | Current subscription |
| `GET /v1/billing/usage` | JWT (analyst+) | Current-period usage vs. quota |
| `GET /v1/analytics/kpis` | JWT | FM8: alert volume, FP-rate placeholder, MTTD/MTTR, open/resolved case counts |

## Detection rule condition DSL (FM4)

```json
{"field": "severity_hint", "op": "eq", "value": "critical"}
```

Composable via `all` (AND) / `any` (OR):

```json
{
  "all": [
    {"field": "event_category", "op": "eq", "value": "authentication"},
    {"field": "event_action", "op": "eq", "value": "login_failed"}
  ]
}
```

Supported operators: `eq`, `neq`, `contains`, `in`, `gt`, `gte`, `lt`, `lte`.
`field` resolves against the normalized event's flat attributes
(`event_category`, `event_action`, `severity_hint`, `actor`, `target`,
`source_ip`) or a dotted path into the nested `normalized` document (e.g.
`event.kind`). See `backend/app/services/rule_engine.py`.

## Case status state machine (FM6)

```
new -> investigating -> resolved
                      -> escalated -> investigating
                                   -> resolved
```

`resolved` is terminal. Any transition not shown above returns `409
Conflict`. See `backend/app/models/case.py::CaseStatus`.

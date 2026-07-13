# Roadmap (generic 12-week sprint plan reference)

This is a generic, role-label-only reference plan (no real names), aligned
to the FM1-FM11 / C1-C14 map in `docs/ARCHITECTURE.md`. Treat sprint
boundaries as indicative, not contractual.

## Weeks 1-2 -- Foundation (this repo)
- [1] Tenant/User data model, signup flow, RBAC roles.
- [2] Ingestion endpoint + queue abstraction + normalizer skeleton.
- [3] Application API skeleton, metadata DB schema, CI/CD pipeline, auth/JWT.
- [4] Detection rule engine scaffolding, analytics aggregation skeleton.
- [5] Case/alert data model review, initial data QA checklist.

## Weeks 3-4 -- Vertical slice hardening
- [1] Billing plans/subscription model, checkout flow (mocked Stripe).
- [2] Telemetry store adapter, OCSF/ECS field mapping expansion.
- [3] Rule evaluator correctness + cross-tenant isolation test coverage.
- [4] Case promotion workflow, KPI (MTTD/MTTR) aggregation correctness.
- [5] Data QA pass on ingested/normalized event fixtures.

## Weeks 5-6 -- Detection depth
- [3]/[4] Expand condition DSL (regex/time-window operators), alert dedup tuning.
- [2] Additional ingestion connectors (syslog, cloud audit logs).
- [5] Threat intel indicator model design (FM5) -- design only.
- [1] Dashboard UX pass on Alerts/Cases/Billing pages.

## Weeks 7-8 -- Threat intelligence (FM5)
- [5] Implement `ThreatIndicator` entity + first feed connector.
- [2] Enrichment step wired into the normalizer pipeline.
- [1] Surface enrichment data on alert/case detail views.

## Weeks 9-10 -- SOAR automation (FM7)
- [3]/[4] Playbook + PlaybookRun entities, action registry, human-in-the-loop approval for high-risk actions.
- [3] Wire playbook triggers into rule engine + case escalation.

## Weeks 11 -- ML detection (C8 / FM4 ML part)
- [4] Offline training pipeline against telemetry store.
- [2] Feature pipeline productionization.
- [4] Online scoring wired into alert creation (`Alert.ml_score`).

## Week 12 -- Compliance reporting (FM9) + SSO (FM1 extension)
- [5] Report templates + PDF/CSV export.
- [3] OIDC/SSO provider implementation behind the existing `AuthProvider` interface.
- [1] Final BI/analytics polish for the SaaS Platform Architect's dashboard remit.

## Ongoing, every sprint
- [3] CI/CD, security review, dependency hygiene.
- [5] Data QA on new ingestion/detection surfaces.
- All: keep `docs/ARCHITECTURE.md`'s FM/C status table current.

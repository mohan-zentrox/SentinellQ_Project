# Roadmap

The original 12-week plan is complete: FM1-FM11 and C1-C14 are implemented, with
the exceptions named explicitly below. This document now tracks **what remains**,
ordered by whether it blocks a production deployment.

Role labels only, per team policy (see `docs/TEAM.md`). No real names.

## Completed (was weeks 1-12)

| Sprint | Scope | Outcome |
|---|---|---|
| 1-2 | Foundation: tenancy, auth, ingestion, API, CI | Done, plus Alembic migrations and a readiness endpoint |
| 3-4 | Vertical slice hardening: billing, telemetry store, rule correctness, KPIs | Done, plus subscription lifecycle and atomic metering |
| 5-6 | Detection depth: DSL expansion, dedup tuning, dashboard UX | Done -- `regex`/`cidr`/`exists`/`icontains`/`not_in`/`not` and time-window thresholds; dedup moved to an indexed ledger; 13 UI routes |
| 7-8 | FM5 Threat intelligence | Done -- indicators, feeds, enrichment in the pipeline, intel-addressable rules, staleness handling |
| 9-10 | FM7 SOAR | Done -- playbooks, runs, 7-action registry, two trigger points, dry-run, human-in-the-loop approval |
| 11 | C8 ML detection | Done -- per-tenant frequency baseline with surprisal scoring, versioned registry, explainable alerts |
| 12 | FM9 Compliance + SSO | FM9 done (3 templates, CSV/JSON/HTML, signed downloads). SSO partial -- see below |

Deviations from the original plan, and why:

- **ML is not an isolation forest.** scikit-learn + numpy + scipy is ~100MB of
  compiled wheels against a deliberately pure-Python dependency list, and it
  needs a pickle-loading story that is a real security liability when the
  artifact comes off disk. A frequency baseline with entropy-weighted surprisal
  scoring is genuinely unsupervised, explainable, dependency-free, and fast
  enough to run inline. Swapping in scikit-learn later means implementing
  `train_model`/`score_event` against the same `MLModelVersion` registry.
- **Report export has no native PDF.** CSV/JSON/HTML are implemented; HTML prints
  to PDF from the browser. WeasyPrint/ReportLab would add a large native
  dependency for an equivalent artifact. The seam is `RENDERERS`.
- **Additional ingestion connectors (syslog, cloud audit logs) were not built.**
  The normalizer accepts the field aliases those sources use, and
  `POST /v1/events/ingest` is the integration point, but there are no
  first-party collectors. See "Next" below.

## Blocking a production deployment

- **[3] Finish the OIDC authorization-code exchange.** Everything around it is
  built (per-tenant config, discovery verification, PKCE URL construction, claim
  mapping, JIT provisioning, the `ssoRequired` lockout guards). What remains is in
  `services/sso.py::complete_login`'s docstring: token-endpoint POST, JWKS fetch
  with key rotation, `jwt.decode` with `aud`/`iss` verification, and `nonce`
  matching. It refuses today rather than trusting an unverified ID token, because
  a partial implementation here is an authentication bypass.
- **[1] Real Stripe.** `StripeProvider` raises on use. Webhook signature
  verification is already real and tested, so the remaining work is the two
  provider methods plus a `stripe` dependency.
- **[3] Shared login rate limiting.** In-process today, so N API replicas give an
  attacker N times the budget. Back `LoginRateLimiter` with the Redis already in
  the stack.
- **[3] Multi-process metrics.** `/metrics` is per-process; with multiple uvicorn
  workers a scrape sees one worker's view. Swap in `prometheus-client` with a
  multiprocess collector, or push to an OTLP sidecar. The call sites
  (`metrics.increment` / `metrics.observe`) are the seam.
- **[3] Secrets management.** JWT secret, SMTP credentials and webhook secrets
  come from environment variables. A real deployment wants a secrets manager and
  JWT key rotation (the `tv` claim already supports invalidating tokens, but the
  signing key itself is single and static).
- **[3] CD.** CI builds images but never pushes them. No registry, no
  staging/prod environments, no k8s/Terraform.

## Next, in rough priority order

- **[2] First-party ingestion connectors.** A syslog listener and a cloud-audit-log
  poller (CloudTrail / Azure Activity / GCP Audit). The API side is done; this is
  collector work plus field-mapping expansion in `services/normalizer.py`.
- **[2] Scheduled jobs.** Feed refresh, indicator expiry, ML retraining, refresh-token
  purging and report generation all exist as endpoints or service functions with
  no scheduler. They are deliberately exposed as callable endpoints so they are
  testable; wiring a scheduler (APScheduler in-process, or a cron-triggered
  container) is the remaining step.
- **[2] Async report generation.** `POST /v1/reports` generates inline. The model
  is already a job (`queued -> generating -> ready/failed`), so moving it onto the
  worker is publishing to the queue instead of calling `generate_report`. Needed
  before a 90-day export over a high-volume tenant.
- **[4] Analyst feedback loop for ML.** Alert dismissals are now recorded
  (`dismissed_by_user_id`, `dismiss_reason`), which is the training signal a
  supervised layer would need. Feeding it back to raise per-model thresholds, or
  to train a classifier on top of the baseline, is the natural next step.
- **[1] Dashboard depth.** The trend chart is inline SVG-free bars; richer
  visualization, saved searches, and a per-analyst work queue are open.
- **[5] More report templates.** Per-control evidence packs, per-source data-quality
  reports, and a scheduled email digest (which depends on the scheduler above).
- **[3] Kafka/Redpanda adapter.** `QueueBackend` is the seam, and
  `KafkaQueueBackend` documents what it needs (topic strategy, consumer groups,
  at-least-once with explicit offset commits).
- **[2] ClickHouse or OpenSearch adapter.** `TelemetryStore` is the seam. The
  interesting part is compiling the FM4 condition DSL into a native query instead
  of evaluating it in Python -- which is also what would remove the current scan
  bound on rule runs.
- **[3] SAML 2.0.** Modelled and explicitly rejected at config time. Only worth
  doing for an enterprise IdP that cannot do OIDC.
- **[3] `disable_user_in_idp`.** Blocked on the SSO work above having
  account-write scope. Must stay high-risk and approval-gated.

## Known rough edges

Small, non-blocking, and recorded so they are not rediscovered:

- Frontend tests emit React `act()` warnings from the data hooks' promise chains.
  Deliberately not silenced -- see `frontend/src/test/setup.ts`.
- `PlaybookRun` retains history for deleted playbooks by design, so a run can
  reference a `playbookId` that no longer resolves. The UI handles it; a consumer
  of the API should too.
- `User.email` is globally unique, not per-tenant, because `POST /v1/auth/login`
  takes no tenant selector. Supporting one human in several tenants needs a
  membership table and a tenant selector at login.
- Alerts are retained when their rule is deleted, so `Alert.rule_id` can dangle.
  That is the intended tradeoff: an investigation's evidence should outlive
  someone tidying up a rule.

## Ongoing, every sprint

- [3] CI/CD, security review, dependency hygiene.
- [5] Data QA on new ingestion/detection surfaces, and on indicator freshness and
  false-positive rates (`GET /v1/threat-indicators/stats/summary` is the view).
- All: keep `docs/ARCHITECTURE.md`'s FM/C status table current.

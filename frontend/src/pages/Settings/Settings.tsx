/**
 * FM11: platform administration.
 *
 * Service tokens matter most here. Issuing one previously required an API call,
 * which meant a new tenant could not ingest a single event from the product --
 * the first-run experience was "read the docs and use curl".
 *
 * A freshly-created token's plaintext is shown exactly once and never returned
 * again by any endpoint, so the UI has to say so.
 */
import { useState } from "react";
import { api, queryString } from "../../api/client";
import {
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  PageHeader,
  Pagination,
  Pill,
  Spinner,
  SuccessBanner,
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { formatNumber } from "../../lib/format";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type {
  AuditLogListResponse,
  MLModelOut,
  ServiceTokenOut,
  ServiceTokenSummary,
  SettingsOverview,
  TrainModelResponse,
} from "../../api/types";

/** Local shape; the SSO config endpoint may return null. */
interface SsoConfig {
  id: string;
  issuer: string;
  clientId: string;
  clientSecretEnvVar: string | null;
  isEnabled: boolean;
  ssoRequired: boolean;
  defaultRole: string;
  jitProvisioning: boolean;
  verifiedAt: string | null;
}

const AUDIT_PAGE_SIZE = 25;

export default function Settings() {
  const isOwner = useAuthStore((state) => state.role === "owner");

  const overviewQuery = useApiData(() => api.get<SettingsOverview>("/admin/settings"), []);
  const tokensQuery = useApiData(() => api.get<ServiceTokenSummary[]>("/tenants/me/service-tokens"), []);
  const modelsQuery = useApiData(() => api.get<MLModelOut[]>("/admin/ml-models"), []);
  const ssoQuery = useApiData(
    () => (isOwner ? api.get<SsoConfig | null>("/admin/sso") : Promise.resolve(null)),
    [isOwner],
  );
  const [auditPage, setAuditPage] = useState(1);
  const [auditAction, setAuditAction] = useState("");
  const auditQuery = useApiData(
    () =>
      api.get<AuditLogListResponse>(
        `/admin/audit-log${queryString({ page: auditPage, pageSize: AUDIT_PAGE_SIZE, action: auditAction })}`,
      ),
    [auditPage, auditAction],
  );

  const [tokenName, setTokenName] = useState("");
  const [issuedToken, setIssuedToken] = useState<ServiceTokenOut | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const createToken = useMutation(async (name: string) =>
    api.post<ServiceTokenOut>("/tenants/me/service-tokens", { name }),
  );
  const revokeToken = useMutation(async (tokenId: string) =>
    api.delete(`/tenants/me/service-tokens/${tokenId}`),
  );
  const trainModel = useMutation(async () =>
    api.post<TrainModelResponse>("/admin/ml-models/train", { windowDays: 30, activate: true }),
  );
  const updateModel = useMutation(async (modelId: string, body: Record<string, unknown>) =>
    api.patch<MLModelOut>(`/admin/ml-models/${modelId}`, body),
  );

  const overview = overviewQuery.data;
  const tokens = tokensQuery.data ?? [];
  const models = modelsQuery.data ?? [];
  const actionError = createToken.error ?? revokeToken.error ?? trainModel.error ?? updateModel.error;

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Ingestion credentials, ML models, single sign-on, deployment configuration, and the audit trail." />

      {notice && <SuccessBanner message={notice} />}
      {actionError && <ErrorBanner message={actionError} />}

      {/* ---------------- Service tokens ---------------- */}
      <section>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Ingestion credentials</h2>
        <Card>
          <p className="mb-3 text-sm text-slate-500">
            Machine clients authenticate to <code className="font-mono text-xs">POST /v1/events/ingest</code> with an{" "}
            <code className="font-mono text-xs">X-Service-Token</code> header. Only a hash is stored, so the plaintext is
            shown once and cannot be recovered.
          </p>
          <form
            className="mb-4 flex flex-wrap items-end gap-2"
            onSubmit={async (e) => {
              e.preventDefault();
              const created = await createToken.run(tokenName);
              if (created) {
                setIssuedToken(created);
                setTokenName("");
                tokensQuery.reload();
              }
            }}
          >
            <Field label="Name" hint="Where this credential will be used, e.g. 'syslog-collector-prod'.">
              <input
                className={inputClass}
                required
                value={tokenName}
                onChange={(e) => setTokenName(e.target.value)}
                placeholder="syslog-collector-prod"
              />
            </Field>
            <Button type="submit" disabled={createToken.isPending || !tokenName}>
              Issue token
            </Button>
          </form>

          {issuedToken && (
            <div className="mb-4 rounded border border-amber-300 bg-amber-50 p-3">
              <p className="text-sm font-medium text-amber-900">
                Copy this now -- it will not be shown again.
              </p>
              <code className="mt-2 block overflow-x-auto rounded bg-white px-2 py-1 font-mono text-xs">
                {issuedToken.token}
              </code>
              <p className="mt-2 text-xs text-amber-800">
                Example: <code className="font-mono">curl -H "X-Service-Token: {issuedToken.token.slice(0, 12)}..." -H
                "Content-Type: application/json" -d '{"{"}"events":[{"{"}"source":"my-collector","payload":{"{"}"eventAction":"login_failed"{"}"}{"}"}]{"}"}' /v1/events/ingest</code>
              </p>
              <Button variant="secondary" onClick={() => setIssuedToken(null)}>
                I have copied it
              </Button>
            </div>
          )}

          {tokensQuery.isLoading ? (
            <Spinner />
          ) : tokens.length === 0 ? (
            <EmptyState title="No ingestion credentials yet" hint="Issue one above to start sending telemetry." />
          ) : (
            <Table
              head={
                <tr>
                  <Th>Name</Th>
                  <Th>Status</Th>
                  <Th>Created</Th>
                  <Th />
                </tr>
              }
            >
              {tokens.map((token) => (
                <tr key={token.id}>
                  <Td className="font-medium text-slate-800">{token.name}</Td>
                  <Td>
                    <Pill tone={token.isActive ? "green" : "slate"}>{token.isActive ? "active" : "revoked"}</Pill>
                  </Td>
                  <Td>
                    <TimeAgo value={token.createdAt} />
                  </Td>
                  <Td>
                    {token.isActive && (
                      <Button
                        variant="danger"
                        disabled={revokeToken.isPending}
                        onClick={async () => {
                          if (!window.confirm(`Revoke "${token.name}"? Clients using it stop being able to ingest.`))
                            return;
                          await revokeToken.run(token.id);
                          setNotice(`Token "${token.name}" revoked.`);
                          tokensQuery.reload();
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </section>

      {/* ---------------- ML models ---------------- */}
      <section>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Anomaly detection models</h2>
        <Card>
          <p className="mb-3 text-sm text-slate-500">
            A per-tenant behavioural baseline. Training needs enough history to be meaningful; a model fitted on a
            handful of events would flag almost everything.
            {overview && !overview.mlDetectionEnabled && (
              <>
                {" "}
                ML scoring is currently <strong>off</strong> for this deployment
                (<code className="font-mono text-xs">SENTINELIQ_ML_DETECTION_ENABLED</code>), so a trained model will not
                create alerts until it is enabled.
              </>
            )}
          </p>
          <Button
            disabled={trainModel.isPending}
            onClick={async () => {
              const result = await trainModel.run();
              if (result) {
                setNotice(result.trained ? `Model ${result.model?.version} trained and activated.` : result.detail ?? "");
                modelsQuery.reload();
              }
            }}
          >
            Train on the last 30 days
          </Button>

          {models.length > 0 && (
            <div className="mt-4">
              <Table
                head={
                  <tr>
                    <Th>Version</Th>
                    <Th>Active</Th>
                    <Th>Trained on</Th>
                    <Th>Threshold</Th>
                    <Th>Scored</Th>
                    <Th>Alerts</Th>
                    <Th>When</Th>
                    <Th />
                  </tr>
                }
              >
                {models.map((model) => (
                  <tr key={model.id}>
                    <Td className="font-mono text-xs">{model.version}</Td>
                    <Td>
                      <Pill tone={model.isActive ? "green" : "slate"}>{model.isActive ? "active" : "inactive"}</Pill>
                    </Td>
                    <Td>{formatNumber(model.trainingEventCount)} events</Td>
                    <Td>{model.scoreThreshold.toFixed(2)}</Td>
                    <Td>{formatNumber(model.scoredEventCount)}</Td>
                    <Td>{formatNumber(model.alertCount)}</Td>
                    <Td>
                      <TimeAgo value={model.trainedAt} />
                    </Td>
                    <Td>
                      <div className="flex flex-wrap gap-1">
                        {!model.isActive && (
                          <Button
                            variant="secondary"
                            onClick={async () => {
                              await updateModel.run(model.id, { isActive: true });
                              setNotice(`Model ${model.version} activated.`);
                              modelsQuery.reload();
                            }}
                          >
                            Activate
                          </Button>
                        )}
                        {model.isActive && (
                          <Button
                            variant="secondary"
                            onClick={async () => {
                              await updateModel.run(model.id, { isActive: false });
                              setNotice("ML scoring disabled for this tenant.");
                              modelsQuery.reload();
                            }}
                          >
                            Deactivate
                          </Button>
                        )}
                        <Button
                          variant="secondary"
                          onClick={async () => {
                            const value = window.prompt(
                              "Alert threshold (0-1). Raise it to reduce noise.",
                              String(model.scoreThreshold),
                            );
                            if (!value) return;
                            await updateModel.run(model.id, { scoreThreshold: Number(value) });
                            modelsQuery.reload();
                          }}
                        >
                          Threshold
                        </Button>
                      </div>
                    </Td>
                  </tr>
                ))}
              </Table>
            </div>
          )}
        </Card>
      </section>

      {/* ---------------- SSO ---------------- */}
      {isOwner && (
        <section>
          <h2 className="mb-2 text-sm font-semibold text-slate-700">Single sign-on</h2>
          <SsoPanel
            config={ssoQuery.data}
            isLoading={ssoQuery.isLoading}
            onChanged={(message) => {
              setNotice(message);
              ssoQuery.reload();
            }}
          />
        </section>
      )}

      {/* ---------------- Deployment configuration ---------------- */}
      <section>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Deployment configuration</h2>
        <Card>
          <p className="mb-3 text-sm text-slate-500">
            Which adapters this environment actually resolved. Useful for answering "is detection-on-ingest really on
            here?" without reading the container's environment. Secrets are never included.
          </p>
          {overviewQuery.isLoading ? (
            <Spinner />
          ) : overviewQuery.error ? (
            <ErrorBanner message={overviewQuery.error} />
          ) : overview ? (
            <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
              <ConfigRow label="Environment" value={overview.environment} />
              <ConfigRow label="Queue backend" value={overview.queueBackend} />
              <ConfigRow label="Telemetry store" value={overview.telemetryStoreBackend} />
              <ConfigRow label="Billing provider" value={overview.billingProvider} />
              <ConfigRow label="Auth provider" value={overview.authProvider} />
              <ConfigRow label="Detect on ingest" value={overview.detectionOnIngest} />
              <ConfigRow label="ML detection" value={overview.mlDetectionEnabled} />
              <ConfigRow label="Intel enrichment" value={overview.threatIntelEnrichOnIngest} />
              <ConfigRow label="Automation" value={overview.soarEnabled} />
              <ConfigRow label="High-risk approval" value={overview.soarRequireApprovalForHighRisk} />
              <ConfigRow label="Notify channels" value={overview.notificationChannels.join(", ")} />
              <ConfigRow label="Notify floor" value={overview.notificationMinSeverity} />
              <ConfigRow label="Webhook configured" value={overview.notificationWebhookConfigured} />
              <ConfigRow label="SMTP configured" value={overview.smtpConfigured} />
              <ConfigRow label="Metrics" value={overview.metricsEnabled} />
            </dl>
          ) : null}
        </Card>
      </section>

      {/* ---------------- Audit log ---------------- */}
      <section>
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Audit log</h2>
          <input
            className="rounded border border-slate-300 px-2 py-1 text-sm"
            value={auditAction}
            onChange={(e) => {
              setAuditAction(e.target.value);
              setAuditPage(1);
            }}
            placeholder="Filter by action prefix, e.g. user."
          />
        </div>
        {auditQuery.isLoading ? (
          <Spinner />
        ) : auditQuery.error ? (
          <ErrorBanner message={auditQuery.error} />
        ) : (auditQuery.data?.items.length ?? 0) === 0 ? (
          <EmptyState title="No audit entries for this filter" />
        ) : (
          <>
            <Table
              head={
                <tr>
                  <Th>When</Th>
                  <Th>Action</Th>
                  <Th>Target</Th>
                  <Th>Actor</Th>
                  <Th>Detail</Th>
                </tr>
              }
            >
              {(auditQuery.data?.items ?? []).map((entry) => (
                <tr key={entry.id}>
                  <Td>
                    <TimeAgo value={entry.createdAt} />
                  </Td>
                  <Td className="font-mono text-xs">{entry.action}</Td>
                  <Td className="font-mono text-xs text-slate-500">
                    {entry.targetType}
                    {entry.targetId && ` ${entry.targetId}`}
                  </Td>
                  <Td className="font-mono text-xs text-slate-500">{entry.actorUserId ?? "system"}</Td>
                  <Td className="max-w-md">
                    <code className="block overflow-x-auto text-xs text-slate-500">
                      {JSON.stringify(entry.detail)}
                    </code>
                  </Td>
                </tr>
              ))}
            </Table>
            <Pagination
              page={auditPage}
              pageSize={AUDIT_PAGE_SIZE}
              total={auditQuery.data?.total ?? 0}
              onPageChange={setAuditPage}
            />
          </>
        )}
      </section>
    </div>
  );
}

function ConfigRow({ label, value }: { label: string; value: string | boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-2 border-b border-slate-100 py-1">
      <dt className="text-slate-500">{label}</dt>
      <dd className="font-medium text-slate-800">
        {typeof value === "boolean" ? <Pill tone={value ? "green" : "slate"}>{value ? "on" : "off"}</Pill> : value}
      </dd>
    </div>
  );
}

function SsoPanel({
  config,
  isLoading,
  onChanged,
}: {
  config: SsoConfig | null;
  isLoading: boolean;
  onChanged: (message: string) => void;
}) {
  const [issuer, setIssuer] = useState(config?.issuer ?? "");
  const [clientId, setClientId] = useState(config?.clientId ?? "");
  const [secretEnvVar, setSecretEnvVar] = useState(config?.clientSecretEnvVar ?? "");
  const [isEnabled, setIsEnabled] = useState(config?.isEnabled ?? false);
  const [ssoRequired, setSsoRequired] = useState(config?.ssoRequired ?? false);

  const save = useMutation(async () =>
    api.put<SsoConfig>("/admin/sso", {
      issuer,
      clientId,
      clientSecretEnvVar: secretEnvVar || null,
      isEnabled,
      ssoRequired,
    }),
  );
  const verify = useMutation(async () => api.post<SsoConfig>("/admin/sso/verify"));

  if (isLoading) return <Spinner />;

  return (
    <Card>
      <p className="mb-3 text-sm text-slate-500">
        OIDC configuration for this tenant. The client secret is never stored here -- name the environment variable that
        holds it instead.
      </p>
      {(save.error || verify.error) && <ErrorBanner message={save.error ?? verify.error ?? ""} />}

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Issuer" hint="Must be https. Discovery is read from /.well-known/openid-configuration.">
          <input
            className={inputClass}
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            placeholder="https://acme.okta.com"
          />
        </Field>
        <Field label="Client ID">
          <input className={inputClass} value={clientId} onChange={(e) => setClientId(e.target.value)} />
        </Field>
        <Field label="Client secret env var" hint="e.g. ACME_OIDC_CLIENT_SECRET">
          <input className={inputClass} value={secretEnvVar} onChange={(e) => setSecretEnvVar(e.target.value)} />
        </Field>
        <div className="space-y-2 pt-5">
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={isEnabled} onChange={(e) => setIsEnabled(e.target.checked)} />
            <span>Enabled</span>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={ssoRequired}
              // Guard mirrored from the API: requiring SSO before it is enabled
              // and verified would lock every user out with no recovery.
              disabled={!isEnabled || !config?.verifiedAt}
              onChange={(e) => setSsoRequired(e.target.checked)}
            />
            <span>
              Require SSO{" "}
              <span className="text-slate-500">
                (disables password login{!config?.verifiedAt && "; verify the configuration first"})
              </span>
            </span>
          </label>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button
          disabled={save.isPending || !issuer || !clientId}
          onClick={async () => {
            const saved = await save.run();
            if (saved) onChanged("SSO configuration saved.");
          }}
        >
          Save
        </Button>
        {config && (
          <Button
            variant="secondary"
            disabled={verify.isPending}
            onClick={async () => {
              const verified = await verify.run();
              if (verified) onChanged("SSO discovery verified against the issuer.");
            }}
          >
            Verify with the identity provider
          </Button>
        )}
        {config?.verifiedAt && (
          <span className="text-xs text-emerald-700">
            Verified <TimeAgo value={config.verifiedAt} />
          </span>
        )}
      </div>

      <p className="mt-3 text-xs text-slate-400">
        Claim mapping and just-in-time provisioning are implemented. The authorization-code exchange is not: verifying an
        ID token against the issuer's JWKS is required before a token can be trusted, and shipping it unverified would be
        an authentication bypass.
      </p>
    </Card>
  );
}

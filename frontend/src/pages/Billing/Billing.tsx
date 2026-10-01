/**
 * FM10: plans, checkout, subscription lifecycle and usage.
 *
 * The checkout flow is completable from here: with the mocked provider, the
 * "complete checkout" step calls the dev webhook so the plan actually activates
 * and the quota actually moves. Previously the flow stopped at a dead link to a
 * fake Stripe URL, so the subscription never left `pending` and the quota never
 * changed -- which made the whole FM10 slice untestable through the product.
 */
import { useState } from "react";
import { api } from "../../api/client";
import {
  Button,
  Card,
  ErrorBanner,
  PageHeader,
  Pill,
  Spinner,
  StatusPill,
  SuccessBanner,
  Table,
  Td,
  Th,
} from "../../components/ui";
import { formatNumber } from "../../lib/format";
import { useApiData, useMutation } from "../../hooks/useApi";
import type {
  PlanOut,
  SettingsOverview,
  SubscriptionOut,
  UsageHistoryResponse,
  UsageOut,
} from "../../api/types";

export default function Billing() {
  const plansQuery = useApiData(() => api.get<PlanOut[]>("/billing/plans"), []);
  const usageQuery = useApiData(() => api.get<UsageOut>("/billing/usage"), []);
  const historyQuery = useApiData(() => api.get<UsageHistoryResponse>("/billing/usage/history?months=12"), []);
  const subscriptionQuery = useApiData(
    () =>
      api.get<SubscriptionOut>("/billing/subscription").catch(() => null as SubscriptionOut | null),
    [],
  );
  const overviewQuery = useApiData(
    () => api.get<SettingsOverview>("/admin/settings").catch(() => null as SettingsOverview | null),
    [],
  );

  const [pendingSession, setPendingSession] = useState<{ sessionId: string; checkoutUrl: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const startCheckout = useMutation(async (planSlug: string) =>
    api.post<{ sessionId: string; checkoutUrl: string }>("/billing/checkout", { planSlug }),
  );
  const completeCheckout = useMutation(async (sessionId: string) =>
    api.post<SubscriptionOut>(
      `/billing/webhook/checkout-completed?session_id=${encodeURIComponent(sessionId)}`,
    ),
  );
  const cancel = useMutation(async (immediate: boolean) =>
    api.post<SubscriptionOut>("/billing/subscription/cancel", { immediate }),
  );

  const plans = plansQuery.data ?? [];
  const usage = usageQuery.data;
  const subscription = subscriptionQuery.data;
  const isMockProvider = overviewQuery.data?.billingProvider === "mock_stripe";
  const currentPlanId = subscription?.planId;
  const actionError = startCheckout.error ?? completeCheckout.error ?? cancel.error;

  function reloadAll() {
    usageQuery.reload();
    subscriptionQuery.reload();
    historyQuery.reload();
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Billing" description="Plan, subscription status and metered event usage." />

      {notice && <SuccessBanner message={notice} />}
      {actionError && <ErrorBanner message={actionError} />}

      {usage && (
        <Card>
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Usage this period ({usage.period})
          </div>
          <div className="mt-1 text-2xl font-semibold text-slate-900">
            {formatNumber(usage.eventCount)}
            {usage.monthlyEventQuota !== null && (
              <span className="text-base font-normal text-slate-500">
                {" "}
                / {formatNumber(usage.monthlyEventQuota)}
              </span>
            )}
          </div>
          {usage.percentUsed !== null && (
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className={`h-full ${usage.overQuota ? "bg-red-600" : "bg-brand-600"}`}
                style={{ width: `${Math.min(usage.percentUsed, 100)}%` }}
              />
            </div>
          )}
          {usage.overQuota && (
            <p className="mt-2 text-sm text-red-700">
              Over quota: ingestion is being rejected with 429 until the next period or a plan upgrade.
            </p>
          )}
        </Card>
      )}

      {subscription && (
        <Card>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500">Subscription</p>
              <div className="mt-1 flex items-center gap-2">
                <StatusPill status={subscription.status} />
                {subscription.cancelAtPeriodEnd && <Pill tone="amber">cancels at period end</Pill>}
              </div>
              <p className="mt-1 text-xs text-slate-500">
                {plans.find((plan) => plan.id === subscription.planId)?.name ?? subscription.planId}
                {subscription.currentPeriodEnd &&
                  ` - renews ${new Date(subscription.currentPeriodEnd).toLocaleDateString()}`}
              </p>
            </div>
            {subscription.status === "active" && !subscription.cancelAtPeriodEnd && (
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  disabled={cancel.isPending}
                  onClick={async () => {
                    if (!window.confirm("Cancel at the end of the current period? Access continues until then."))
                      return;
                    const updated = await cancel.run(false);
                    if (updated) {
                      setNotice("Subscription will not renew. Your current quota applies until the period ends.");
                      reloadAll();
                    }
                  }}
                >
                  Cancel at period end
                </Button>
                <Button
                  variant="danger"
                  disabled={cancel.isPending}
                  onClick={async () => {
                    if (
                      !window.confirm(
                        "Downgrade immediately? Ingestion will start being rejected once you are over the free quota.",
                      )
                    )
                      return;
                    const updated = await cancel.run(true);
                    if (updated) {
                      setNotice("Subscription canceled and plan downgraded.");
                      reloadAll();
                    }
                  }}
                >
                  Cancel now
                </Button>
              </div>
            )}
          </div>
        </Card>
      )}

      <div>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Plans</h2>
        {plansQuery.isLoading ? (
          <Spinner />
        ) : (
          <div className="grid gap-4 sm:grid-cols-3">
            {plans.map((plan) => {
              const isCurrent = plan.id === currentPlanId;
              return (
                <Card key={plan.id} className={isCurrent ? "border-brand-400 ring-1 ring-brand-200" : ""}>
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-900">{plan.name}</span>
                    {isCurrent && <Pill tone="green">current</Pill>}
                  </div>
                  <div className="mt-1 text-2xl font-semibold text-brand-700">
                    ${(plan.priceCents / 100).toFixed(0)}
                    <span className="text-sm font-normal text-slate-500">/mo</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    {formatNumber(plan.monthlyEventQuota)} events / month
                  </div>
                  <Button
                    className="mt-4 w-full"
                    disabled={startCheckout.isPending || isCurrent}
                    onClick={async () => {
                      const session = await startCheckout.run(plan.slug);
                      if (session) {
                        setPendingSession(session);
                        setNotice(null);
                      }
                    }}
                  >
                    {isCurrent ? "Current plan" : "Choose plan"}
                  </Button>
                </Card>
              );
            })}
          </div>
        )}
      </div>

      {pendingSession && (
        <Card className="border-amber-300 bg-amber-50">
          <p className="text-sm font-medium text-amber-900">Checkout session created</p>
          <p className="mt-1 break-all text-xs text-amber-800">{pendingSession.checkoutUrl}</p>
          {isMockProvider ? (
            <>
              <p className="mt-2 text-xs text-amber-800">
                This deployment uses the mocked billing provider, so there is no real payment page. Completing the
                session here runs the same activation path a verified Stripe webhook would.
              </p>
              <div className="mt-3 flex gap-2">
                <Button
                  disabled={completeCheckout.isPending}
                  onClick={async () => {
                    const updated = await completeCheckout.run(pendingSession.sessionId);
                    if (updated) {
                      setPendingSession(null);
                      setNotice("Subscription activated and quota updated.");
                      reloadAll();
                    }
                  }}
                >
                  Complete checkout (mock)
                </Button>
                <Button variant="secondary" onClick={() => setPendingSession(null)}>
                  Cancel
                </Button>
              </div>
            </>
          ) : (
            <p className="mt-2 text-xs text-amber-800">
              Continue at the provider's checkout page. Activation arrives as a signature-verified webhook.
            </p>
          )}
        </Card>
      )}

      {(historyQuery.data?.entries.length ?? 0) > 0 && (
        <div>
          <h2 className="mb-2 text-sm font-semibold text-slate-700">Usage history</h2>
          <Table
            head={
              <tr>
                <Th>Period</Th>
                <Th>Events ingested</Th>
              </tr>
            }
          >
            {(historyQuery.data?.entries ?? []).map((entry) => (
              <tr key={entry.period}>
                <Td className="font-mono text-xs">{entry.period}</Td>
                <Td>{formatNumber(entry.eventCount)}</Td>
              </tr>
            ))}
          </Table>
        </div>
      )}
    </div>
  );
}

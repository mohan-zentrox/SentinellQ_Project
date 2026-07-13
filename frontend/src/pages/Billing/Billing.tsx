import { useEffect, useState } from "react";
import { api, ApiError } from "../../api/client";
import type { PlanOut, UsageOut } from "../../api/types";

export default function Billing() {
  const [plans, setPlans] = useState<PlanOut[]>([]);
  const [usage, setUsage] = useState<UsageOut | null>(null);
  const [checkoutUrl, setCheckoutUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<PlanOut[]>("/billing/plans").then(setPlans).catch(() => setPlans([]));
    api
      .get<UsageOut>("/billing/usage")
      .then(setUsage)
      .catch(() => setUsage(null));
  }, []);

  async function startCheckout(planSlug: string) {
    setError(null);
    setCheckoutUrl(null);
    try {
      // FM10: mocked Stripe Checkout session -- see
      // backend/app/services/billing_provider.py::MockStripeProvider.
      const session = await api.post<{ sessionId: string; checkoutUrl: string }>("/billing/checkout", {
        planSlug,
      });
      setCheckoutUrl(session.checkoutUrl);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Checkout failed");
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-lg font-semibold text-slate-900">Billing</h1>

      {usage && (
        <div className="rounded-lg border border-slate-200 bg-white p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">Usage this period ({usage.period})</div>
          <div className="mt-1 text-2xl font-semibold text-slate-900">
            {usage.eventCount.toLocaleString()}
            {usage.monthlyEventQuota !== null && (
              <span className="text-base font-normal text-slate-500"> / {usage.monthlyEventQuota.toLocaleString()}</span>
            )}
          </div>
          {usage.percentUsed !== null && (
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full bg-brand-600"
                style={{ width: `${Math.min(usage.percentUsed, 100)}%` }}
              />
            </div>
          )}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        {plans.map((plan) => (
          <div key={plan.id} className="rounded-lg border border-slate-200 bg-white p-4">
            <div className="font-semibold text-slate-900">{plan.name}</div>
            <div className="mt-1 text-2xl font-semibold text-brand-700">
              ${(plan.priceCents / 100).toFixed(0)}
              <span className="text-sm font-normal text-slate-500">/mo</span>
            </div>
            <div className="mt-1 text-xs text-slate-500">
              {plan.monthlyEventQuota.toLocaleString()} events / month
            </div>
            <button
              onClick={() => startCheckout(plan.slug)}
              className="mt-4 w-full rounded-md bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
            >
              Choose plan
            </button>
          </div>
        ))}
      </div>

      {checkoutUrl && (
        <p className="text-sm text-slate-600">
          Mocked Stripe Checkout session created:{" "}
          <a className="text-brand-600 hover:underline" href={checkoutUrl}>
            {checkoutUrl}
          </a>
        </p>
      )}
      {error && <p className="text-sm text-severity-critical">{error}</p>}
    </div>
  );
}

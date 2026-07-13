import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAlertsStore } from "../../store/alertsStore";
import SeverityBadge from "../../components/SeverityBadge";
import { api, ApiError } from "../../api/client";
import type { CaseOut, KPIResponse } from "../../api/types";

export default function AlertsDashboard() {
  const { items, total, isLoading, error, fetchAlerts } = useAlertsStore();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [kpis, setKpis] = useState<KPIResponse | null>(null);
  const [promoteError, setPromoteError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    fetchAlerts();
    api
      .get<KPIResponse>("/analytics/kpis")
      .then(setKpis)
      .catch(() => setKpis(null));
  }, [fetchAlerts]);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function promoteSelection() {
    setPromoteError(null);
    try {
      const created = await api.post<CaseOut>("/alerts/promote", {
        alertIds: Array.from(selected),
        title: `Case from ${selected.size} alert(s)`,
      });
      navigate(`/cases/${created.id}`);
    } catch (err) {
      setPromoteError(err instanceof ApiError ? err.message : "Failed to promote alerts");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-900">Alerts</h1>
        <p className="text-sm text-slate-500">{total} alert(s) in this tenant.</p>
      </div>

      {kpis && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <KpiTile label="Alert volume" value={kpis.alertVolume.toString()} />
          <KpiTile label="False-positive rate" value={`${(kpis.falsePositiveRate * 100).toFixed(1)}%`} />
          <KpiTile label="MTTD" value={formatSeconds(kpis.mttdSeconds)} />
          <KpiTile label="MTTR" value={formatSeconds(kpis.mttrSeconds)} />
        </div>
      )}

      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-500">{selected.size} selected</span>
        <button
          onClick={promoteSelection}
          disabled={selected.size === 0}
          className="rounded-md bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-40"
        >
          Promote to case
        </button>
      </div>
      {promoteError && <p className="text-sm text-severity-critical">{promoteError}</p>}

      {isLoading && <p className="text-sm text-slate-500">Loading alerts...</p>}
      {error && <p className="text-sm text-severity-critical">{error}</p>}

      <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
        <table className="min-w-full divide-y divide-slate-200 text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2"></th>
              <th className="px-3 py-2">Title</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Created</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {items.map((alert) => (
              <tr key={alert.id}>
                <td className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={selected.has(alert.id)}
                    onChange={() => toggle(alert.id)}
                    disabled={alert.status === "promoted"}
                  />
                </td>
                <td className="px-3 py-2 font-medium text-slate-800">{alert.title}</td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="px-3 py-2 capitalize text-slate-600">{alert.status}</td>
                <td className="px-3 py-2 text-slate-500">{new Date(alert.createdAt).toLocaleString()}</td>
              </tr>
            ))}
            {items.length === 0 && !isLoading && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-slate-400">
                  No alerts yet. Ingest events and run a detection rule to see alerts here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function KpiTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-900">{value}</div>
    </div>
  );
}

function formatSeconds(seconds: number | null): string {
  if (seconds === null) return "n/a";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

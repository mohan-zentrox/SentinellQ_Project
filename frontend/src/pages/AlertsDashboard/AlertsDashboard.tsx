/**
 * FM4/FM6/FM8: the analyst's queue.
 *
 * Triage is the addition that matters here. The previous version could only list
 * alerts and promote them into a case; there was no way to dismiss a false
 * positive, which is both the most common triage outcome and the input FM8's
 * false-positive-rate KPI needs.
 */
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, queryString } from "../../api/client";
import SeverityBadge from "../../components/SeverityBadge";
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
  StatTile,
  StatusPill,
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { formatDuration, formatNumber } from "../../lib/format";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type {
  AlertListResponse,
  AlertTimeseriesResponse,
  CaseOut,
  KPIResponse,
} from "../../api/types";

const PAGE_SIZE = 25;

export default function AlertsDashboard() {
  const navigate = useNavigate();
  const canTriage = useAuthStore((state) => state.hasRole("analyst"));

  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const alertsQuery = useApiData(
    () =>
      api.get<AlertListResponse>(
        `/alerts${queryString({ page, pageSize: PAGE_SIZE, status, severity, detectionSource: source })}`,
      ),
    [page, status, severity, source],
  );
  const kpiQuery = useApiData(() => api.get<KPIResponse>("/analytics/kpis?days=30"), []);
  const trendQuery = useApiData(
    () => api.get<AlertTimeseriesResponse>("/analytics/alerts/timeseries?days=14&bucketHours=24"),
    [],
  );

  const dismiss = useMutation(async (ids: string[], reason: string) => {
    if (ids.length === 1) {
      await api.patch(`/alerts/${ids[0]}`, { status: "dismissed", reason });
    } else {
      await api.patch("/alerts", { alertIds: ids, status: "dismissed", reason });
    }
  });

  const reopen = useMutation(async (id: string) => {
    await api.patch(`/alerts/${id}`, { status: "open" });
  });

  const promote = useMutation(async (ids: string[], title: string) => {
    return api.post<CaseOut>("/alerts/promote", { alertIds: ids, title });
  });

  // Memoized on the response object, not on a freshly-derived array: `data?.items
  // ?? []` produces a new array identity every render, which would make the memo
  // recompute every time and defeat the point.
  const alerts = useMemo(() => alertsQuery.data?.items ?? [], [alertsQuery.data]);
  const selectableIds = useMemo(
    () => alerts.filter((alert) => alert.status !== "promoted").map((alert) => alert.id),
    [alerts],
  );
  const allSelected = selectableIds.length > 0 && selectableIds.every((id) => selected.has(id));

  function toggle(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(selectableIds));
  }

  function refreshAll() {
    setSelected(new Set());
    alertsQuery.reload();
    kpiQuery.reload();
    trendQuery.reload();
  }

  async function handleBulkDismiss() {
    const ids = [...selected];
    if (ids.length === 0) return;
    const reason = window.prompt(`Dismiss ${ids.length} alert(s) as a false positive. Reason:`, "");
    if (reason === null) return;
    await dismiss.run(ids, reason);
    refreshAll();
  }

  async function handlePromote() {
    const ids = [...selected];
    if (ids.length === 0) return;
    const title = window.prompt("Case title", alerts.find((a) => a.id === ids[0])?.title ?? "Investigation");
    if (!title) return;
    const created = await promote.run(ids, title);
    if (created) {
      navigate(`/cases/${created.id}`);
    } else {
      refreshAll();
    }
  }

  const kpis = kpiQuery.data;
  const mutationError = dismiss.error ?? promote.error ?? reopen.error;

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Detections raised by rules and ML scoring, newest first. Dismissing an alert records it as a false positive and feeds the detection-quality KPI."
        actions={<Button variant="secondary" onClick={refreshAll}>Refresh</Button>}
      />

      {kpis && (
        <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <StatTile label="Alert volume (30d)" value={formatNumber(kpis.alertVolume)} />
          <StatTile
            label="False positive rate"
            value={`${(kpis.falsePositiveRate * 100).toFixed(1)}%`}
            hint={`${kpis.dismissedAlerts} dismissed`}
          />
          <StatTile label="MTTD" value={formatDuration(kpis.mttdSeconds)} hint="mean time to detect" />
          <StatTile label="MTTR" value={formatDuration(kpis.mttrSeconds)} hint="mean time to resolve" />
          <StatTile label="Open cases" value={formatNumber(kpis.openCases)} hint={`${kpis.resolvedCases} resolved`} />
        </div>
      )}

      {trendQuery.data && trendQuery.data.buckets.some((bucket) => bucket.count > 0) && (
        <Card className="mb-5">
          <p className="mb-3 text-xs font-medium uppercase tracking-wide text-slate-500">
            Alert volume, last 14 days
          </p>
          <Sparkbars buckets={trendQuery.data.buckets} />
        </Card>
      )}

      <Card className="mb-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Status">
            <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} className={inputClass}>
              <option value="">All</option>
              <option value="open">Open</option>
              <option value="dismissed">Dismissed</option>
              <option value="promoted">Promoted</option>
            </select>
          </Field>
          <Field label="Severity">
            <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }} className={inputClass}>
              <option value="">All</option>
              {["critical", "high", "medium", "low", "informational"].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Detection source">
            <select value={source} onChange={(e) => { setSource(e.target.value); setPage(1); }} className={inputClass}>
              <option value="">All</option>
              <option value="rule">Rule</option>
              <option value="ml">ML</option>
              <option value="manual">Manual</option>
            </select>
          </Field>
        </div>
      </Card>

      {mutationError && <ErrorBanner message={mutationError} />}
      {alertsQuery.error && <ErrorBanner message={alertsQuery.error} />}

      {canTriage && selected.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded border border-brand-200 bg-brand-50 px-3 py-2 text-sm">
          <span className="font-medium text-brand-900">{selected.size} selected</span>
          <Button onClick={handlePromote} disabled={promote.isPending}>
            Promote to case
          </Button>
          <Button variant="secondary" onClick={handleBulkDismiss} disabled={dismiss.isPending}>
            Dismiss as false positive
          </Button>
          <Button variant="secondary" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </div>
      )}

      {alertsQuery.isLoading ? (
        <Spinner label="Loading alerts..." />
      ) : alerts.length === 0 ? (
        <EmptyState
          title="No alerts match these filters"
          hint="Ingest events via POST /v1/events/ingest with a service token, and enable at least one detection rule."
        />
      ) : (
        <>
          <Table
            head={
              <tr>
                <Th className="w-8">
                  {canTriage && (
                    <input
                      type="checkbox"
                      aria-label="Select all alerts"
                      checked={allSelected}
                      onChange={toggleAll}
                    />
                  )}
                </Th>
                <Th>Severity</Th>
                <Th>Title</Th>
                <Th>Source</Th>
                <Th>Status</Th>
                <Th>Events</Th>
                <Th>Raised</Th>
                <Th />
              </tr>
            }
          >
            {alerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-slate-50">
                <Td>
                  {canTriage && alert.status !== "promoted" && (
                    <input
                      type="checkbox"
                      aria-label={`Select ${alert.title}`}
                      checked={selected.has(alert.id)}
                      onChange={() => toggle(alert.id)}
                    />
                  )}
                </Td>
                <Td>
                  <SeverityBadge severity={alert.severity} />
                </Td>
                <Td>
                  <button
                    type="button"
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                    className="text-left font-medium text-brand-700 hover:underline"
                  >
                    {alert.title}
                  </button>
                  {alert.dismissReason && (
                    <p className="mt-0.5 text-xs text-slate-400">Dismissed: {alert.dismissReason}</p>
                  )}
                </Td>
                <Td>
                  <Pill tone={alert.detectionSource === "ml" ? "purple" : "slate"}>{alert.detectionSource}</Pill>
                  {alert.mlScore !== null && (
                    <span className="ml-1 text-xs text-slate-400">{alert.mlScore.toFixed(2)}</span>
                  )}
                </Td>
                <Td>
                  <StatusPill status={alert.status} />
                </Td>
                <Td>{alert.eventIds.length}</Td>
                <Td>
                  <TimeAgo value={alert.createdAt} />
                </Td>
                <Td>
                  {canTriage && alert.status === "dismissed" && (
                    <Button
                      variant="secondary"
                      onClick={async () => {
                        await reopen.run(alert.id);
                        refreshAll();
                      }}
                    >
                      Reopen
                    </Button>
                  )}
                  {alert.caseId && (
                    <Button variant="secondary" onClick={() => navigate(`/cases/${alert.caseId}`)}>
                      View case
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={alertsQuery.data?.total ?? 0}
            onPageChange={(next) => {
              setSelected(new Set());
              setPage(next);
            }}
          />
        </>
      )}
    </div>
  );
}

/**
 * Inline bar chart.
 *
 * Plain divs rather than a charting dependency: this is one series of at most 14
 * buckets, and the alternative is shipping a chart library to draw 14
 * rectangles. Heights are percentages of the window maximum, and every bar
 * carries an accessible label so the data is available without the visual.
 */
function Sparkbars({ buckets }: { buckets: AlertTimeseriesResponse["buckets"] }) {
  const max = Math.max(...buckets.map((bucket) => bucket.count), 1);
  return (
    <div className="flex h-24 items-end gap-1" role="img" aria-label="Daily alert counts for the last 14 days">
      {buckets.map((bucket) => {
        const height = Math.round((bucket.count / max) * 100);
        const day = new Date(bucket.bucketStart).toLocaleDateString(undefined, {
          month: "short",
          day: "numeric",
        });
        return (
          <div key={bucket.bucketStart} className="flex flex-1 flex-col items-center justify-end gap-1">
            <div
              className="w-full rounded-t bg-brand-500"
              style={{ height: `${Math.max(height, bucket.count > 0 ? 4 : 1)}%` }}
              title={`${day}: ${bucket.count} alert(s)`}
            />
            <span className="text-[10px] text-slate-400">{bucket.count}</span>
          </div>
        );
      })}
    </div>
  );
}

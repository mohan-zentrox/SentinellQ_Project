/**
 * FM3: the telemetry explorer.
 *
 * `GET /v1/events` has always existed; nothing in the UI called it, so ingested
 * telemetry was invisible unless an analyst used curl. This is the page that
 * makes an ingestion problem diagnosable -- "did my collector's events arrive,
 * and were they normalized correctly?"
 */
import { useState } from "react";
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
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { formatNumber } from "../../lib/format";
import { useApiData, useDebounced } from "../../hooks/useApi";
import type { EventDetailOut, EventListResponse } from "../../api/types";

const PAGE_SIZE = 50;

export default function Events() {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Debounced so typing a filter does not issue a request per keystroke.
  const debouncedSearch = useDebounced(search, 350);
  const debouncedCategory = useDebounced(category, 350);

  const query = useApiData(
    () =>
      api.get<EventListResponse>(
        `/events${queryString({
          page,
          pageSize: PAGE_SIZE,
          severity,
          eventCategory: debouncedCategory,
          search: debouncedSearch,
        })}`,
      ),
    [page, severity, debouncedCategory, debouncedSearch],
  );

  const detailQuery = useApiData(
    () => (selectedId ? api.get<EventDetailOut>(`/events/${selectedId}`) : Promise.resolve(null)),
    [selectedId],
  );

  const ingestionQuery = useApiData(
    () =>
      api.get<{
        totalEvents: number;
        enrichedEvents: number;
        bySource: Record<string, number>;
        bySeverity: Record<string, number>;
      }>("/analytics/ingestion?days=7"),
    [],
  );

  const events = query.data?.items ?? [];

  return (
    <div>
      <PageHeader
        title="Telemetry"
        description="Normalized security events, newest first. Use this to confirm a collector is delivering and that normalization mapped its fields correctly."
        actions={<Button variant="secondary" onClick={query.reload}>Refresh</Button>}
      />

      {ingestionQuery.data && (
        <Card className="mb-4">
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">Last 7 days</p>
          <div className="flex flex-wrap gap-4 text-sm">
            <span>
              <strong>{formatNumber(ingestionQuery.data.totalEvents)}</strong> events
            </span>
            <span className="text-slate-500">
              {formatNumber(ingestionQuery.data.enrichedEvents)} enriched
            </span>
            {Object.entries(ingestionQuery.data.bySource).map(([source, count]) => (
              <Pill key={source}>
                {source}: {count}
              </Pill>
            ))}
          </div>
        </Card>
      )}

      <Card className="mb-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Severity">
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className={inputClass}
            >
              <option value="">All</option>
              {["critical", "high", "medium", "low", "informational"].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Category">
            <input
              className={inputClass}
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setPage(1);
              }}
              placeholder="authentication"
            />
          </Field>
          <Field label="Search" hint="Matches actor, target, source IP or action.">
            <input
              className={inputClass}
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="alice"
            />
          </Field>
        </div>
      </Card>

      {query.error && <ErrorBanner message={query.error} />}

      {query.isLoading ? (
        <Spinner label="Loading telemetry..." />
      ) : events.length === 0 ? (
        <EmptyState
          title="No events match these filters"
          hint="Issue a service token under Settings, then POST a batch to /v1/events/ingest with the X-Service-Token header."
        />
      ) : (
        <>
          <Table
            head={
              <tr>
                <Th>Occurred</Th>
                <Th>Severity</Th>
                <Th>Category / action</Th>
                <Th>Actor</Th>
                <Th>Source IP</Th>
                <Th>Collector</Th>
                <Th>Intel</Th>
              </tr>
            }
          >
            {events.map((event) => (
              <tr
                key={event.id}
                onClick={() => setSelectedId(event.id === selectedId ? null : event.id)}
                className={`cursor-pointer hover:bg-slate-50 ${event.id === selectedId ? "bg-brand-50" : ""}`}
              >
                <Td>
                  <TimeAgo value={event.occurredAt} />
                </Td>
                <Td>
                  <SeverityBadge severity={event.severityHint} />
                </Td>
                <Td>
                  <span className="text-slate-500">{event.eventCategory}</span> / {event.eventAction}
                </Td>
                <Td>{event.actor ?? "--"}</Td>
                <Td className="font-mono text-xs">{event.sourceIp ?? "--"}</Td>
                <Td className="text-xs text-slate-500">{event.source}</Td>
                <Td>
                  {event.enrichment?.matched ? (
                    <Pill tone="red">{event.enrichment.maxConfidence}</Pill>
                  ) : (
                    <span className="text-xs text-slate-300">--</span>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
          <Pagination page={page} pageSize={PAGE_SIZE} total={query.data?.total ?? 0} onPageChange={setPage} />
        </>
      )}

      {selectedId && (
        <Card className="mt-4">
          <div className="mb-2 flex items-center justify-between">
            <p className="text-sm font-semibold text-slate-700">Event {selectedId}</p>
            <Button variant="secondary" onClick={() => setSelectedId(null)}>
              Close
            </Button>
          </div>
          {detailQuery.isLoading ? (
            <Spinner />
          ) : detailQuery.error ? (
            <ErrorBanner message={detailQuery.error} />
          ) : detailQuery.data ? (
            <div className="grid gap-4 lg:grid-cols-2">
              <div>
                <p className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">
                  Raw payload (as received)
                </p>
                <pre className="max-h-72 overflow-auto rounded bg-slate-900 p-3 text-xs text-slate-100">
                  {JSON.stringify(detailQuery.data.rawPayload, null, 2)}
                </pre>
              </div>
              <div>
                <p className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">
                  Normalized (OCSF/ECS-aligned)
                </p>
                <pre className="max-h-72 overflow-auto rounded bg-slate-900 p-3 text-xs text-slate-100">
                  {JSON.stringify(detailQuery.data.normalized, null, 2)}
                </pre>
                {detailQuery.data.enrichment && (
                  <>
                    <p className="mt-3 mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">
                      Threat intel enrichment
                    </p>
                    <pre className="max-h-48 overflow-auto rounded bg-slate-900 p-3 text-xs text-slate-100">
                      {JSON.stringify(detailQuery.data.enrichment, null, 2)}
                    </pre>
                  </>
                )}
              </div>
            </div>
          ) : null}
        </Card>
      )}
    </div>
  );
}

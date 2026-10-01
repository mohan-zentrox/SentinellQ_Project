/**
 * FM5: threat intelligence -- indicators, feeds, and the lookup tool.
 *
 * The lookup is more useful than it looks: an indicator only matches when its
 * normalized form matches, so "is this value actually matchable?" is the question
 * an analyst needs answered after adding one, and before writing a rule that
 * thresholds on enrichment.
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
  StatTile,
  SuccessBanner,
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { useApiData, useDebounced, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type { Enrichment, FeedOut, IndicatorListResponse, IndicatorStats } from "../../api/types";

const PAGE_SIZE = 25;
const TYPES = ["ip", "domain", "url", "file_hash", "cve", "email"];

export default function ThreatIntel() {
  const canEdit = useAuthStore((state) => state.hasRole("analyst"));
  const canManageFeeds = useAuthStore((state) => state.hasRole("admin"));

  const [page, setPage] = useState(1);
  const [type, setType] = useState("");
  const [search, setSearch] = useState("");
  const [activeOnly, setActiveOnly] = useState(true);
  const debouncedSearch = useDebounced(search, 350);

  const indicatorsQuery = useApiData(
    () =>
      api.get<IndicatorListResponse>(
        `/threat-indicators${queryString({
          page,
          pageSize: PAGE_SIZE,
          indicatorType: type,
          search: debouncedSearch,
          activeOnly,
        })}`,
      ),
    [page, type, debouncedSearch, activeOnly],
  );
  const statsQuery = useApiData(() => api.get<IndicatorStats>("/threat-indicators/stats/summary"), []);
  const feedsQuery = useApiData(
    () => (canEdit ? api.get<FeedOut[]>("/threat-feeds") : Promise.resolve([])),
    [canEdit],
  );

  // Add form
  const [newType, setNewType] = useState("ip");
  const [newValue, setNewValue] = useState("");
  const [newConfidence, setNewConfidence] = useState("75");
  const [newSeverity, setNewSeverity] = useState("high");
  const [newTags, setNewTags] = useState("");
  const [notice, setNotice] = useState<string | null>(null);

  // Lookup
  const [lookupType, setLookupType] = useState("ip");
  const [lookupValue, setLookupValue] = useState("");
  const [lookupResult, setLookupResult] = useState<{ matched: boolean; enrichment: Enrichment } | null>(null);

  const addIndicator = useMutation(async () =>
    api.post("/threat-indicators", {
      indicatorType: newType,
      value: newValue,
      confidence: Number(newConfidence),
      severity: newSeverity,
      tags: newTags
        .split(",")
        .map((tag) => tag.trim())
        .filter(Boolean),
    }),
  );
  const deactivate = useMutation(async (id: string) => api.delete(`/threat-indicators/${id}`));
  const lookup = useMutation(async (indicatorType: string, value: string) =>
    api.get<{ matched: boolean; enrichment: Enrichment }>(
      `/threat-indicators/preview/${indicatorType}/${encodeURIComponent(value)}`,
    ),
  );
  const refreshFeed = useMutation(async (feedId: string) =>
    api.post<{ created: number; updated: number; status: string | null }>(`/threat-feeds/${feedId}/refresh`),
  );
  const expireStale = useMutation(async () => api.post<{ expired: number }>("/threat-indicators/expire-stale"));

  const indicators = indicatorsQuery.data ?? null;
  const stats = statsQuery.data;

  function reloadAll() {
    indicatorsQuery.reload();
    statsQuery.reload();
    feedsQuery.reload();
  }

  return (
    <div>
      <PageHeader
        title="Threat intelligence"
        description="Indicators are matched against every ingested event before detection runs, so a rule can threshold on reputation."
        actions={
          canManageFeeds ? (
            <Button
              variant="secondary"
              disabled={expireStale.isPending}
              onClick={async () => {
                const result = await expireStale.run();
                if (result) {
                  setNotice(`${result.expired} stale indicator(s) deactivated.`);
                  reloadAll();
                }
              }}
            >
              Expire stale indicators
            </Button>
          ) : undefined
        }
      />

      {notice && <SuccessBanner message={notice} />}
      {(addIndicator.error || deactivate.error || refreshFeed.error || expireStale.error) && (
        <ErrorBanner
          message={addIndicator.error ?? deactivate.error ?? refreshFeed.error ?? expireStale.error ?? ""}
        />
      )}

      {stats && (
        <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatTile label="Active indicators" value={stats.activeIndicators} />
          <StatTile label="Inactive / expired" value={stats.inactiveIndicators} />
          <StatTile label="Ever matched" value={stats.everMatched} />
          <StatTile
            label="Match rate"
            value={`${(stats.matchRate * 100).toFixed(1)}%`}
            hint="indicators that have matched at least once"
          />
        </div>
      )}

      <div className="mb-5 grid gap-4 lg:grid-cols-2">
        {canEdit && (
          <Card>
            <p className="mb-3 text-sm font-semibold text-slate-700">Add an indicator</p>
            <form
              className="space-y-3"
              onSubmit={async (e) => {
                e.preventDefault();
                const created = await addIndicator.run();
                if (created) {
                  setNotice(`Indicator ${newValue} saved.`);
                  setNewValue("");
                  setNewTags("");
                  reloadAll();
                }
              }}
            >
              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="Type">
                  <select className={inputClass} value={newType} onChange={(e) => setNewType(e.target.value)}>
                    {TYPES.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Value">
                  <input
                    className={inputClass}
                    required
                    value={newValue}
                    onChange={(e) => setNewValue(e.target.value)}
                    placeholder="203.0.113.7"
                  />
                </Field>
                <Field label="Confidence (0-100)">
                  <input
                    className={inputClass}
                    type="number"
                    min={0}
                    max={100}
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(e.target.value)}
                  />
                </Field>
                <Field label="Severity">
                  <select className={inputClass} value={newSeverity} onChange={(e) => setNewSeverity(e.target.value)}>
                    {["informational", "low", "medium", "high", "critical"].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
              <Field label="Tags" hint="Comma separated. Rules can match on these.">
                <input
                  className={inputClass}
                  value={newTags}
                  onChange={(e) => setNewTags(e.target.value)}
                  placeholder="c2, ransomware"
                />
              </Field>
              <Button type="submit" disabled={addIndicator.isPending || !newValue}>
                Add indicator
              </Button>
            </form>
          </Card>
        )}

        <Card>
          <p className="mb-3 text-sm font-semibold text-slate-700">Look up a value</p>
          <form
            className="space-y-3"
            onSubmit={async (e) => {
              e.preventDefault();
              const result = await lookup.run(lookupType, lookupValue);
              if (result) setLookupResult(result);
            }}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Type">
                <select className={inputClass} value={lookupType} onChange={(e) => setLookupType(e.target.value)}>
                  {TYPES.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Value">
                <input
                  className={inputClass}
                  required
                  value={lookupValue}
                  onChange={(e) => setLookupValue(e.target.value)}
                  placeholder="203.0.113.7"
                />
              </Field>
            </div>
            <Button type="submit" variant="secondary" disabled={lookup.isPending || !lookupValue}>
              Check our intel
            </Button>
          </form>
          {lookup.error && <ErrorBanner message={lookup.error} />}
          {lookupResult && (
            <div className="mt-3 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm">
              {lookupResult.matched ? (
                <>
                  <Pill tone="red">match</Pill>
                  <p className="mt-1">
                    {lookupResult.enrichment.indicatorCount} indicator(s), max confidence{" "}
                    {lookupResult.enrichment.maxConfidence}
                    {lookupResult.enrichment.tags.length > 0 && ` - ${lookupResult.enrichment.tags.join(", ")}`}
                  </p>
                </>
              ) : (
                <>
                  <Pill>no match</Pill>
                  <p className="mt-1 text-slate-500">
                    This value is not in the tenant's active indicators. An event carrying it will be enriched with
                    `matched: false`.
                  </p>
                </>
              )}
            </div>
          )}
        </Card>
      </div>

      {canEdit && (feedsQuery.data ?? []).length > 0 && (
        <Card className="mb-5">
          <p className="mb-3 text-sm font-semibold text-slate-700">Feeds</p>
          <Table
            head={
              <tr>
                <Th>Feed</Th>
                <Th>Provider</Th>
                <Th>Indicators</Th>
                <Th>Last refreshed</Th>
                <Th>Status</Th>
                <Th />
              </tr>
            }
          >
            {(feedsQuery.data ?? []).map((feed) => (
              <tr key={feed.id}>
                <Td>
                  <p className="font-medium text-slate-800">{feed.name}</p>
                  <p className="text-xs text-slate-400">{feed.slug}</p>
                </Td>
                <Td>{feed.provider}</Td>
                <Td>{feed.indicatorCount}</Td>
                <Td>
                  <TimeAgo value={feed.lastRefreshedAt} />
                </Td>
                <Td className="max-w-xs text-xs">
                  {feed.lastRefreshStatus ? (
                    <span className={feed.lastRefreshStatus.startsWith("error") ? "text-red-600" : "text-slate-500"}>
                      {feed.lastRefreshStatus}
                    </span>
                  ) : (
                    <span className="text-slate-400">never refreshed</span>
                  )}
                </Td>
                <Td>
                  <Button
                    variant="secondary"
                    disabled={refreshFeed.isPending}
                    onClick={async () => {
                      const result = await refreshFeed.run(feed.id);
                      if (result) {
                        setNotice(`${feed.slug}: ${result.status ?? "refreshed"}`);
                        reloadAll();
                      }
                    }}
                  >
                    Refresh
                  </Button>
                </Td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      <Card className="mb-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Type">
            <select
              className={inputClass}
              value={type}
              onChange={(e) => {
                setType(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All</option>
              {TYPES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Search">
            <input
              className={inputClass}
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              placeholder="203.0.113"
            />
          </Field>
          <Field label="Include inactive">
            <select
              className={inputClass}
              value={activeOnly ? "active" : "all"}
              onChange={(e) => {
                setActiveOnly(e.target.value === "active");
                setPage(1);
              }}
            >
              <option value="active">Active only</option>
              <option value="all">Active and inactive</option>
            </select>
          </Field>
        </div>
      </Card>

      {indicatorsQuery.error && <ErrorBanner message={indicatorsQuery.error} />}

      {indicatorsQuery.isLoading ? (
        <Spinner label="Loading indicators..." />
      ) : (indicators?.items.length ?? 0) === 0 ? (
        <EmptyState
          title="No indicators yet"
          hint="Add one above, or configure a feed to import them automatically."
        />
      ) : (
        <>
          <Table
            head={
              <tr>
                <Th>Type</Th>
                <Th>Value</Th>
                <Th>Confidence</Th>
                <Th>Source</Th>
                <Th>Tags</Th>
                <Th>Matches</Th>
                <Th>Expires</Th>
                <Th />
              </tr>
            }
          >
            {(indicators?.items ?? []).map((indicator) => (
              <tr key={indicator.id} className={indicator.isActive ? "" : "opacity-50"}>
                <Td>
                  <Pill>{indicator.indicatorType}</Pill>
                </Td>
                <Td className="font-mono text-xs">{indicator.value}</Td>
                <Td>{indicator.confidence}</Td>
                <Td className="text-xs text-slate-500">{indicator.source}</Td>
                <Td className="text-xs">{indicator.tags.join(", ") || "--"}</Td>
                <Td>{indicator.matchCount}</Td>
                <Td>
                  <TimeAgo value={indicator.expiresAt} />
                </Td>
                <Td>
                  {canEdit && indicator.isActive && (
                    <Button
                      variant="secondary"
                      disabled={deactivate.isPending}
                      onClick={async () => {
                        await deactivate.run(indicator.id);
                        reloadAll();
                      }}
                    >
                      Deactivate
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
          <Pagination page={page} pageSize={PAGE_SIZE} total={indicators?.total ?? 0} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}

/**
 * FM6: the case queue.
 *
 * There was previously no way to reach a case except by following the redirect
 * from promoting an alert -- a case detail route existed with nothing linking to
 * it, so any case whose URL an analyst had not kept was effectively lost.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, queryString } from "../../api/client";
import SeverityBadge from "../../components/SeverityBadge";
import {
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  PageHeader,
  Pagination,
  Spinner,
  StatusPill,
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { formatDuration } from "../../lib/format";
import { useApiData } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type { CaseListResponse, UserOut } from "../../api/types";

const PAGE_SIZE = 25;

export default function CasesList() {
  const navigate = useNavigate();
  const userId = useAuthStore((state) => state.userId);
  const canSeeUsers = useAuthStore((state) => state.hasRole("admin"));

  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [scope, setScope] = useState<"all" | "mine" | "unassigned">("all");

  const query = useApiData(
    () =>
      api.get<CaseListResponse>(
        `/cases${queryString({
          page,
          pageSize: PAGE_SIZE,
          status,
          severity,
          assigneeUserId: scope === "mine" ? userId ?? undefined : undefined,
          unassigned: scope === "unassigned" ? true : undefined,
        })}`,
      ),
    [page, status, severity, scope, userId],
  );

  // Only admins can list users, so analysts see raw ids rather than a failed
  // request. The API would 403 and the page would show an error for something
  // that is purely cosmetic.
  const usersQuery = useApiData(
    () => (canSeeUsers ? api.get<UserOut[]>("/tenants/me/users") : Promise.resolve([])),
    [canSeeUsers],
  );
  const emailById = new Map((usersQuery.data ?? []).map((user) => [user.id, user.email]));

  const cases = query.data?.items ?? [];

  return (
    <div>
      <PageHeader
        title="Cases"
        description="Investigations promoted from alerts, with their state-machine status and resolution time."
      />

      <Card className="mb-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Status">
            <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} className={inputClass}>
              <option value="">All</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="escalated">Escalated</option>
              <option value="resolved">Resolved</option>
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
          <Field label="Assignment">
            <select
              value={scope}
              onChange={(e) => {
                setScope(e.target.value as typeof scope);
                setPage(1);
              }}
              className={inputClass}
            >
              <option value="all">Everyone</option>
              <option value="mine">Assigned to me</option>
              <option value="unassigned">Unassigned</option>
            </select>
          </Field>
        </div>
      </Card>

      {query.error && <ErrorBanner message={query.error} />}

      {query.isLoading ? (
        <Spinner label="Loading cases..." />
      ) : cases.length === 0 ? (
        <EmptyState
          title="No cases match these filters"
          hint="Promote one or more alerts from the Alerts page to open a case."
        />
      ) : (
        <>
          <Table
            head={
              <tr>
                <Th>Severity</Th>
                <Th>Title</Th>
                <Th>Status</Th>
                <Th>Assignee</Th>
                <Th>Alerts</Th>
                <Th>Opened</Th>
                <Th>Time to resolve</Th>
              </tr>
            }
          >
            {cases.map((item) => {
              const resolutionSeconds =
                item.resolvedAt !== null
                  ? (new Date(item.resolvedAt).getTime() - new Date(item.createdAt).getTime()) / 1000
                  : null;
              return (
                <tr
                  key={item.id}
                  className="cursor-pointer hover:bg-slate-50"
                  onClick={() => navigate(`/cases/${item.id}`)}
                >
                  <Td>
                    <SeverityBadge severity={item.severity} />
                  </Td>
                  <Td className="font-medium text-brand-700">{item.title}</Td>
                  <Td>
                    <StatusPill status={item.status} />
                  </Td>
                  <Td>
                    {item.assigneeUserId
                      ? emailById.get(item.assigneeUserId) ?? item.assigneeUserId
                      : <span className="text-slate-400">unassigned</span>}
                  </Td>
                  <Td>{item.alertIds.length}</Td>
                  <Td>
                    <TimeAgo value={item.createdAt} />
                  </Td>
                  <Td>{resolutionSeconds === null ? "--" : formatDuration(resolutionSeconds)}</Td>
                </tr>
              );
            })}
          </Table>
          <Pagination page={page} pageSize={PAGE_SIZE} total={query.data?.total ?? 0} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}

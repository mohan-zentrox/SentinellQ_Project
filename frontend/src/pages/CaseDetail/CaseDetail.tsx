/**
 * FM6: case detail -- timeline, comments, assignment, state machine.
 *
 * Adds the two things the investigation workflow could not do: record an analyst
 * note (the timeline supported `comment` entries but only automation could write
 * one), and assign the case to a real user picked from the tenant's roster.
 */
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../../api/client";
import SeverityBadge from "../../components/SeverityBadge";
import {
  Button,
  Card,
  ErrorBanner,
  Field,
  PageHeader,
  Pill,
  Spinner,
  StatusPill,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { formatDuration } from "../../lib/format";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type { AlertOut, CaseOut, CaseTimelineEntryOut, UserOut } from "../../api/types";

/** Mirrors backend CaseStatus.TRANSITIONS; the server is still the authority
 *  and returns 409 on an invalid transition. */
const TRANSITIONS: Record<string, string[]> = {
  new: ["investigating"],
  investigating: ["resolved", "escalated"],
  escalated: ["investigating", "resolved"],
  resolved: [],
};

const ENTRY_TONES: Record<string, string> = {
  created: "blue",
  status_change: "amber",
  comment: "slate",
  assignment: "purple",
};

export default function CaseDetail() {
  const { caseId = "" } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const canAct = useAuthStore((state) => state.hasRole("analyst"));
  const canSeeUsers = useAuthStore((state) => state.hasRole("admin"));

  const [comment, setComment] = useState("");
  const [note, setNote] = useState("");

  const caseQuery = useApiData(() => api.get<CaseOut>(`/cases/${caseId}`), [caseId]);
  const timelineQuery = useApiData(
    () => api.get<CaseTimelineEntryOut[]>(`/cases/${caseId}/timeline`),
    [caseId],
  );
  const usersQuery = useApiData(
    () => (canSeeUsers ? api.get<UserOut[]>("/tenants/me/users") : Promise.resolve([])),
    [canSeeUsers],
  );

  const caseData = caseQuery.data;
  const alertsQuery = useApiData(
    () =>
      caseData && caseData.alertIds.length > 0
        ? Promise.all(caseData.alertIds.slice(0, 20).map((id) => api.get<AlertOut>(`/alerts/${id}`)))
        : Promise.resolve([]),
    [caseData?.id, caseData?.alertIds.length],
  );

  const transition = useMutation(async (status: string, transitionNote: string) => {
    await api.patch<CaseOut>(`/cases/${caseId}/status`, { status, note: transitionNote || undefined });
  });
  const addComment = useMutation(async (message: string) => {
    await api.post<CaseTimelineEntryOut>(`/cases/${caseId}/comments`, { message });
  });
  const assign = useMutation(async (assigneeUserId: string | null) => {
    await api.patch<CaseOut>(`/cases/${caseId}/assign`, { assigneeUserId });
  });

  function reload() {
    caseQuery.reload();
    timelineQuery.reload();
  }

  if (caseQuery.isLoading) return <Spinner label="Loading case..." />;
  if (caseQuery.error) return <ErrorBanner message={caseQuery.error} />;
  if (!caseData) return <ErrorBanner message="Case not found" />;

  const availableTransitions = TRANSITIONS[caseData.status] ?? [];
  const users = usersQuery.data ?? [];
  const emailById = new Map(users.map((user) => [user.id, user.email]));
  const resolutionSeconds =
    caseData.resolvedAt !== null
      ? (new Date(caseData.resolvedAt).getTime() - new Date(caseData.createdAt).getTime()) / 1000
      : null;
  const actionError = transition.error ?? addComment.error ?? assign.error;

  return (
    <div className="space-y-5">
      <PageHeader
        title={caseData.title}
        description={caseData.description || "No description."}
        actions={
          <Button variant="secondary" onClick={() => navigate("/cases")}>
            Back to cases
          </Button>
        }
      />

      {actionError && <ErrorBanner message={actionError} />}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Status</p>
          <div className="mt-1">
            <StatusPill status={caseData.status} />
          </div>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Severity</p>
          <div className="mt-1">
            <SeverityBadge severity={caseData.severity} />
          </div>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Opened</p>
          <p className="mt-1 text-sm">
            <TimeAgo value={caseData.createdAt} />
          </p>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Time to resolve</p>
          <p className="mt-1 text-sm text-slate-700">
            {resolutionSeconds === null ? "unresolved" : formatDuration(resolutionSeconds)}
          </p>
        </Card>
      </div>

      {canAct && availableTransitions.length > 0 && (
        <Card>
          <p className="mb-2 text-sm font-semibold text-slate-700">Advance this case</p>
          <div className="space-y-2">
            <Field label="Note (optional)" hint="Recorded on the timeline alongside the transition.">
              <input
                className={inputClass}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="What did you find?"
              />
            </Field>
            <div className="flex flex-wrap gap-2">
              {availableTransitions.map((status) => (
                <Button
                  key={status}
                  variant={status === "escalated" ? "danger" : "primary"}
                  disabled={transition.isPending}
                  onClick={async () => {
                    await transition.run(status, note);
                    setNote("");
                    reload();
                  }}
                >
                  Move to {status}
                </Button>
              ))}
            </div>
          </div>
        </Card>
      )}

      {caseData.status === "resolved" && (
        <Card>
          <p className="text-sm text-slate-500">
            This case is resolved. `resolved` is terminal in the FM6 state machine, so there are no further
            transitions.
          </p>
        </Card>
      )}

      {canAct && (
        <Card>
          <p className="mb-2 text-sm font-semibold text-slate-700">Assignment</p>
          <div className="flex flex-wrap items-end gap-2">
            {canSeeUsers ? (
              <Field label="Assignee">
                <select
                  className={inputClass}
                  value={caseData.assigneeUserId ?? ""}
                  onChange={async (e) => {
                    await assign.run(e.target.value || null);
                    reload();
                  }}
                >
                  <option value="">Unassigned</option>
                  {users
                    .filter((user) => user.isActive)
                    .map((user) => (
                      <option key={user.id} value={user.id}>
                        {user.email} ({user.role})
                      </option>
                    ))}
                </select>
              </Field>
            ) : (
              <p className="text-sm text-slate-600">
                Assigned to:{" "}
                {caseData.assigneeUserId
                  ? emailById.get(caseData.assigneeUserId) ?? caseData.assigneeUserId
                  : "unassigned"}
              </p>
            )}
          </div>
        </Card>
      )}

      <Card>
        <p className="mb-2 text-sm font-semibold text-slate-700">
          Contributing alerts ({caseData.alertIds.length})
        </p>
        {alertsQuery.isLoading ? (
          <Spinner label="Loading alerts..." />
        ) : (alertsQuery.data ?? []).length === 0 ? (
          <p className="text-sm text-slate-500">This case was opened without linked alerts.</p>
        ) : (
          <ul className="space-y-2">
            {(alertsQuery.data ?? []).map((alert) => (
              <li key={alert.id} className="flex items-center justify-between gap-3 text-sm">
                <button
                  type="button"
                  onClick={() => navigate(`/alerts/${alert.id}`)}
                  className="text-left font-medium text-brand-700 hover:underline"
                >
                  {alert.title}
                </button>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={alert.severity} />
                  <Pill tone={alert.detectionSource === "ml" ? "purple" : "slate"}>{alert.detectionSource}</Pill>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      {canAct && (
        <Card>
          <p className="mb-2 text-sm font-semibold text-slate-700">Add a note</p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              if (!comment.trim()) return;
              await addComment.run(comment.trim());
              setComment("");
              timelineQuery.reload();
            }}
            className="space-y-2"
          >
            <textarea
              className={inputClass}
              rows={3}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Findings, actions taken, next steps..."
              maxLength={2000}
            />
            <Button type="submit" disabled={addComment.isPending || !comment.trim()}>
              Add note
            </Button>
          </form>
        </Card>
      )}

      <div>
        <h2 className="mb-2 text-sm font-semibold text-slate-700">Timeline</h2>
        {timelineQuery.isLoading ? (
          <Spinner />
        ) : (
          <ol className="space-y-3 border-l border-slate-200 pl-4">
            {(timelineQuery.data ?? []).map((entry) => (
              <li key={entry.id} className="text-sm">
                <div className="flex items-center gap-2">
                  <Pill tone={ENTRY_TONES[entry.entryType] ?? "slate"}>{entry.entryType.replace(/_/g, " ")}</Pill>
                  <span className="text-xs text-slate-400">
                    <TimeAgo value={entry.createdAt} />
                    {entry.actorUserId && ` - ${emailById.get(entry.actorUserId) ?? entry.actorUserId}`}
                  </span>
                </div>
                <div className="mt-1 text-slate-800">{entry.message}</div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}

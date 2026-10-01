/**
 * FM7: SOAR playbooks and the approval queue.
 *
 * The approval queue is the human-in-the-loop surface. A run containing a
 * high-risk action sits in `pending_approval` until someone approves it, so this
 * page is where that decision gets made -- and it shows exactly which actions
 * will execute, because approving blind defeats the gate.
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
import { StatusPill } from "../../components/ui";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type {
  ActionRegistryEntry,
  PlaybookOut,
  PlaybookRunDetailOut,
  PlaybookRunListResponse,
} from "../../api/types";

const PAGE_SIZE = 25;
const TRIGGERS = ["alert_created", "case_escalated", "case_created", "manual"];

export default function Playbooks() {
  const canManage = useAuthStore((state) => state.hasRole("admin"));

  const playbooksQuery = useApiData(() => api.get<PlaybookOut[]>("/playbooks"), []);
  const actionsQuery = useApiData(() => api.get<ActionRegistryEntry[]>("/playbook-actions"), []);
  const [runPage, setRunPage] = useState(1);
  const [runStatus, setRunStatus] = useState("");
  const runsQuery = useApiData(
    () =>
      api.get<PlaybookRunListResponse>(
        `/playbook-runs${queryString({ page: runPage, pageSize: PAGE_SIZE, status: runStatus })}`,
      ),
    [runPage, runStatus],
  );
  const pendingQuery = useApiData(
    () => api.get<PlaybookRunListResponse>("/playbook-runs?status=pending_approval&pageSize=50"),
    [],
  );

  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [trigger, setTrigger] = useState("alert_created");
  const [actionsText, setActionsText] = useState(
    JSON.stringify([{ action: "create_indicator", params: { confidence: 80 } }], null, 2),
  );
  const [conditionText, setConditionText] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [expandedRun, setExpandedRun] = useState<string | null>(null);

  const detailQuery = useApiData(
    () => (expandedRun ? api.get<PlaybookRunDetailOut>(`/playbook-runs/${expandedRun}`) : Promise.resolve(null)),
    [expandedRun],
  );

  const create = useMutation(async (body: Record<string, unknown>) => api.post<PlaybookOut>("/playbooks", body));
  const toggle = useMutation(async (playbook: PlaybookOut) =>
    api.patch(`/playbooks/${playbook.id}`, { isEnabled: !playbook.isEnabled }),
  );
  const setDryRunMode = useMutation(async (playbook: PlaybookOut) =>
    api.patch(`/playbooks/${playbook.id}`, { dryRun: !playbook.dryRun }),
  );
  const remove = useMutation(async (playbookId: string) => api.delete(`/playbooks/${playbookId}`));
  const approve = useMutation(async (runId: string) => api.post(`/playbook-runs/${runId}/approve`));
  const reject = useMutation(async (runId: string, reason: string) =>
    api.post(`/playbook-runs/${runId}/reject`, { reason }),
  );

  function reloadAll() {
    playbooksQuery.reload();
    runsQuery.reload();
    pendingQuery.reload();
  }

  async function handleCreate() {
    setFormError(null);
    let actions: unknown;
    try {
      actions = JSON.parse(actionsText);
    } catch (err) {
      setFormError(`Actions is not valid JSON: ${err instanceof Error ? err.message : "parse error"}`);
      return;
    }
    let triggerCondition: unknown = undefined;
    if (conditionText.trim()) {
      try {
        triggerCondition = JSON.parse(conditionText);
      } catch (err) {
        setFormError(`Trigger condition is not valid JSON: ${err instanceof Error ? err.message : "parse error"}`);
        return;
      }
    }
    const created = await create.run({ name, description, trigger, actions, triggerCondition, dryRun });
    if (created) {
      setNotice(
        created.requiresApproval
          ? `Playbook "${created.name}" created. It contains a high-risk action, so every run will wait for approval.`
          : `Playbook "${created.name}" created.`,
      );
      setShowForm(false);
      setName("");
      reloadAll();
    }
  }

  const playbooks = playbooksQuery.data ?? [];
  const pending = pendingQuery.data?.items ?? [];
  const actionError = toggle.error ?? remove.error ?? approve.error ?? reject.error ?? setDryRunMode.error;

  return (
    <div>
      <PageHeader
        title="Automation"
        description="Playbooks react to new alerts and case escalations. Any playbook containing a high-risk action requires a named human to approve each run -- there is no fully-autonomous destructive automation."
        actions={
          canManage ? (
            <Button onClick={() => setShowForm(!showForm)}>{showForm ? "Cancel" : "New playbook"}</Button>
          ) : undefined
        }
      />

      {notice && <SuccessBanner message={notice} />}
      {actionError && <ErrorBanner message={actionError} />}

      {pending.length > 0 && (
        <Card className="mb-5 border-purple-200 bg-purple-50">
          <p className="mb-2 text-sm font-semibold text-purple-900">
            {pending.length} run(s) awaiting approval
          </p>
          <p className="mb-3 text-xs text-purple-800">
            Nothing has executed for these. Review what each would do before approving.
          </p>
          <div className="space-y-2">
            {pending.map((run) => (
              <div key={run.id} className="rounded border border-purple-200 bg-white px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="font-medium text-slate-800">
                      {playbooks.find((p) => p.id === run.playbookId)?.name ?? run.playbookId}
                    </p>
                    <p className="text-xs text-slate-500">
                      triggered by {run.trigger.replace(/_/g, " ")}
                      {run.subjectId && ` on ${run.subjectId}`} - <TimeAgo value={run.createdAt} />
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="secondary" onClick={() => setExpandedRun(expandedRun === run.id ? null : run.id)}>
                      {expandedRun === run.id ? "Hide" : "What would run?"}
                    </Button>
                    {canManage && (
                      <>
                        <Button
                          disabled={approve.isPending}
                          onClick={async () => {
                            await approve.run(run.id);
                            setNotice("Run approved and executed.");
                            reloadAll();
                          }}
                        >
                          Approve
                        </Button>
                        <Button
                          variant="danger"
                          disabled={reject.isPending}
                          onClick={async () => {
                            const reason = window.prompt("Why reject this run?", "");
                            if (reason === null) return;
                            await reject.run(run.id, reason);
                            setNotice("Run rejected; nothing executed.");
                            reloadAll();
                          }}
                        >
                          Reject
                        </Button>
                      </>
                    )}
                  </div>
                </div>
                {expandedRun === run.id && (
                  <div className="mt-2 border-t border-slate-100 pt-2">
                    <PlannedActions
                      playbook={playbooks.find((p) => p.id === run.playbookId)}
                      registry={actionsQuery.data ?? []}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {showForm && canManage && (
        <Card className="mb-5">
          <p className="mb-3 text-sm font-semibold text-slate-700">New playbook</p>
          {(formError || create.error) && <ErrorBanner message={formError ?? create.error ?? ""} />}
          <div className="grid gap-3 lg:grid-cols-2">
            <div className="space-y-3">
              <Field label="Name">
                <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} />
              </Field>
              <Field label="Description">
                <input
                  className={inputClass}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </Field>
              <Field label="Trigger">
                <select className={inputClass} value={trigger} onChange={(e) => setTrigger(e.target.value)}>
                  {TRIGGERS.map((value) => (
                    <option key={value} value={value}>
                      {value.replace(/_/g, " ")}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="Trigger condition (optional JSON)"
                hint="Same condition DSL as detection rules, evaluated against the triggering alert or case."
              >
                <textarea
                  className={`${inputClass} font-mono`}
                  rows={4}
                  value={conditionText}
                  onChange={(e) => setConditionText(e.target.value)}
                  placeholder='{"field": "severity_hint", "op": "eq", "value": "critical"}'
                  spellCheck={false}
                />
              </Field>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                <span>
                  Dry run <span className="text-slate-500">(records intended effects without performing them)</span>
                </span>
              </label>
            </div>
            <div className="space-y-3">
              <Field label="Actions (JSON array)">
                <textarea
                  className={`${inputClass} font-mono`}
                  rows={10}
                  value={actionsText}
                  onChange={(e) => setActionsText(e.target.value)}
                  spellCheck={false}
                />
              </Field>
              <div>
                <p className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-500">Available actions</p>
                <ul className="space-y-1 text-xs">
                  {(actionsQuery.data ?? []).map((entry) => (
                    <li key={entry.name} className="flex items-start gap-2">
                      <code className="font-mono text-slate-700">{entry.name}</code>
                      {entry.isHighRisk && <Pill tone="red">needs approval</Pill>}
                      <span className="text-slate-500">{entry.description}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
          <div className="mt-4 flex gap-2">
            <Button onClick={handleCreate} disabled={create.isPending || !name}>
              Create playbook
            </Button>
            <Button variant="secondary" onClick={() => setShowForm(false)}>
              Cancel
            </Button>
          </div>
        </Card>
      )}

      {playbooksQuery.error && <ErrorBanner message={playbooksQuery.error} />}

      <h2 className="mb-2 text-sm font-semibold text-slate-700">Playbooks</h2>
      {playbooksQuery.isLoading ? (
        <Spinner />
      ) : playbooks.length === 0 ? (
        <EmptyState
          title="No playbooks configured"
          hint="Start with dry run enabled to see what a playbook would do before it does it."
        />
      ) : (
        <Table
          head={
            <tr>
              <Th>Name</Th>
              <Th>Trigger</Th>
              <Th>Actions</Th>
              <Th>Mode</Th>
              <Th>Runs</Th>
              <Th>Last run</Th>
              <Th />
            </tr>
          }
        >
          {playbooks.map((playbook) => (
            <tr key={playbook.id}>
              <Td>
                <p className="font-medium text-slate-800">{playbook.name}</p>
                {playbook.description && <p className="text-xs text-slate-500">{playbook.description}</p>}
              </Td>
              <Td className="text-xs">{playbook.trigger.replace(/_/g, " ")}</Td>
              <Td className="text-xs">
                {playbook.actions.map((action) => action.action).join(", ")}
                {playbook.requiresApproval && (
                  <div className="mt-1">
                    <Pill tone="red">needs approval</Pill>
                  </div>
                )}
              </Td>
              <Td>
                <div className="flex flex-col gap-1">
                  <Pill tone={playbook.isEnabled ? "green" : "slate"}>
                    {playbook.isEnabled ? "enabled" : "disabled"}
                  </Pill>
                  {playbook.dryRun && <Pill tone="purple">dry run</Pill>}
                </div>
              </Td>
              <Td>{playbook.runCount}</Td>
              <Td>
                <TimeAgo value={playbook.lastRunAt} />
              </Td>
              <Td>
                {canManage && (
                  <div className="flex flex-wrap gap-1">
                    <Button
                      variant="secondary"
                      onClick={async () => {
                        await toggle.run(playbook);
                        reloadAll();
                      }}
                    >
                      {playbook.isEnabled ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      variant="secondary"
                      onClick={async () => {
                        await setDryRunMode.run(playbook);
                        reloadAll();
                      }}
                    >
                      {playbook.dryRun ? "Go live" : "Dry run"}
                    </Button>
                    <Button
                      variant="danger"
                      onClick={async () => {
                        if (!window.confirm(`Delete "${playbook.name}"? Run history is kept.`)) return;
                        await remove.run(playbook.id);
                        reloadAll();
                      }}
                    >
                      Delete
                    </Button>
                  </div>
                )}
              </Td>
            </tr>
          ))}
        </Table>
      )}

      <div className="mt-6">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Run history</h2>
          <select
            className="rounded border border-slate-300 px-2 py-1 text-sm"
            value={runStatus}
            onChange={(e) => {
              setRunStatus(e.target.value);
              setRunPage(1);
            }}
          >
            <option value="">All statuses</option>
            {["pending_approval", "succeeded", "failed", "partial", "rejected"].map((value) => (
              <option key={value} value={value}>
                {value.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>
        {runsQuery.isLoading ? (
          <Spinner />
        ) : (runsQuery.data?.items.length ?? 0) === 0 ? (
          <EmptyState title="No runs yet" />
        ) : (
          <>
            <Table
              head={
                <tr>
                  <Th>Playbook</Th>
                  <Th>Status</Th>
                  <Th>Trigger</Th>
                  <Th>Subject</Th>
                  <Th>When</Th>
                  <Th>Approved by</Th>
                  <Th />
                </tr>
              }
            >
              {(runsQuery.data?.items ?? []).map((run) => (
                <tr key={run.id}>
                  <Td>{playbooks.find((p) => p.id === run.playbookId)?.name ?? run.playbookId}</Td>
                  <Td>
                    <StatusPill status={run.status} />
                    {run.dryRun && (
                      <span className="ml-1">
                        <Pill tone="purple">dry</Pill>
                      </span>
                    )}
                  </Td>
                  <Td className="text-xs">{run.trigger.replace(/_/g, " ")}</Td>
                  <Td className="font-mono text-xs">{run.subjectId ?? "--"}</Td>
                  <Td>
                    <TimeAgo value={run.createdAt} />
                  </Td>
                  <Td className="font-mono text-xs">{run.approvedByUserId ?? "--"}</Td>
                  <Td>
                    <Button variant="secondary" onClick={() => setExpandedRun(expandedRun === run.id ? null : run.id)}>
                      {expandedRun === run.id ? "Hide" : "Details"}
                    </Button>
                  </Td>
                </tr>
              ))}
            </Table>
            <Pagination
              page={runPage}
              pageSize={PAGE_SIZE}
              total={runsQuery.data?.total ?? 0}
              onPageChange={setRunPage}
            />
          </>
        )}
      </div>

      {expandedRun && detailQuery.data && (
        <Card className="mt-4">
          <div className="mb-2 flex items-center justify-between">
            <p className="text-sm font-semibold text-slate-700">Run {expandedRun}</p>
            <Button variant="secondary" onClick={() => setExpandedRun(null)}>
              Close
            </Button>
          </div>
          {detailQuery.data.actions.length === 0 ? (
            <p className="text-sm text-slate-500">
              No actions have executed for this run{detailQuery.data.status === "pending_approval" && " (awaiting approval)"}.
            </p>
          ) : (
            <Table
              head={
                <tr>
                  <Th>#</Th>
                  <Th>Action</Th>
                  <Th>Status</Th>
                  <Th>Result</Th>
                  <Th>Took</Th>
                </tr>
              }
            >
              {detailQuery.data.actions.map((record) => (
                <tr key={record.id}>
                  <Td>{record.sequence}</Td>
                  <Td>
                    <code className="font-mono text-xs">{record.action}</code>
                    {record.isHighRisk && (
                      <span className="ml-1">
                        <Pill tone="red">high risk</Pill>
                      </span>
                    )}
                  </Td>
                  <Td>
                    <StatusPill status={record.status} />
                  </Td>
                  <Td className="max-w-md">
                    {record.error ? (
                      <span className="text-xs text-red-600">{record.error}</span>
                    ) : (
                      <code className="block overflow-x-auto text-xs text-slate-500">
                        {JSON.stringify(record.result)}
                      </code>
                    )}
                  </Td>
                  <Td className="text-xs">{record.durationMs !== null ? `${record.durationMs}ms` : "--"}</Td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}
    </div>
  );
}

function PlannedActions({
  playbook,
  registry,
}: {
  playbook: PlaybookOut | undefined;
  registry: ActionRegistryEntry[];
}) {
  if (!playbook) {
    return <p className="text-xs text-slate-500">The playbook for this run no longer exists.</p>;
  }
  const byName = new Map(registry.map((entry) => [entry.name, entry]));
  return (
    <ol className="space-y-1 text-xs">
      {playbook.actions.map((action, index) => {
        const entry = byName.get(action.action);
        return (
          <li key={`${action.action}-${index}`} className="flex flex-wrap items-center gap-2">
            <span className="text-slate-400">{index + 1}.</span>
            <code className="font-mono text-slate-700">{action.action}</code>
            {entry?.isHighRisk && <Pill tone="red">high risk</Pill>}
            {Object.keys(action.params).length > 0 && (
              <code className="text-slate-500">{JSON.stringify(action.params)}</code>
            )}
          </li>
        );
      })}
    </ol>
  );
}

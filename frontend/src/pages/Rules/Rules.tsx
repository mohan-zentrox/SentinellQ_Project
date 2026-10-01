/**
 * FM4: detection rule management.
 *
 * Rules were previously creatable only by hand-crafting an API call, and there
 * was no way to edit, disable or delete one. The dry-run panel is the part that
 * makes authoring safe: an analyst can see how many of the last N events a
 * condition would match *before* enabling it, rather than finding out from the
 * resulting alert volume.
 */
import { useState } from "react";
import { api } from "../../api/client";
import SeverityBadge from "../../components/SeverityBadge";
import {
  Button,
  Card,
  EmptyState,
  ErrorBanner,
  Field,
  PageHeader,
  Pill,
  Spinner,
  SuccessBanner,
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type { DetectionCoverageResponse, DetectionRuleOut, RuleRunResponse, RuleTestResponse } from "../../api/types";

const EXAMPLES: { label: string; condition: string }[] = [
  {
    label: "Critical severity",
    condition: JSON.stringify({ field: "severity_hint", op: "eq", value: "critical" }, null, 2),
  },
  {
    label: "Brute force (5 failures / 10 min per actor)",
    condition: JSON.stringify(
      {
        field: "event_action",
        op: "eq",
        value: "login_failed",
        window: { minutes: 10, count: 5, groupBy: "actor" },
      },
      null,
      2,
    ),
  },
  {
    label: "Known-bad source IP (threat intel)",
    condition: JSON.stringify({ field: "enrichment.maxConfidence", op: "gte", value: 80 }, null, 2),
  },
  {
    label: "Service account outside the corporate range",
    condition: JSON.stringify(
      {
        all: [
          { field: "actor", op: "regex", value: "^svc-" },
          { not: { field: "source_ip", op: "cidr", value: "10.0.0.0/8" } },
        ],
      },
      null,
      2,
    ),
  },
];

export default function Rules() {
  const canEdit = useAuthStore((state) => state.hasRole("analyst"));
  const canDelete = useAuthStore((state) => state.hasRole("admin"));

  const rulesQuery = useApiData(() => api.get<DetectionRuleOut[]>("/detection-rules"), []);
  const coverageQuery = useApiData(
    () => api.get<DetectionCoverageResponse>("/analytics/detection-coverage"),
    [],
  );

  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [conditionText, setConditionText] = useState(EXAMPLES[0].condition);
  const [windowMinutes, setWindowMinutes] = useState("");
  const [testResult, setTestResult] = useState<RuleTestResponse | null>(null);
  const [runResult, setRunResult] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const save = useMutation(async (body: Record<string, unknown>, ruleId: string | null) => {
    if (ruleId) return api.patch<DetectionRuleOut>(`/detection-rules/${ruleId}`, body);
    return api.post<DetectionRuleOut>("/detection-rules", body);
  });
  const toggle = useMutation(async (rule: DetectionRuleOut) => {
    await api.patch(`/detection-rules/${rule.id}`, { isEnabled: !rule.isEnabled });
  });
  const remove = useMutation(async (ruleId: string) => {
    await api.delete(`/detection-rules/${ruleId}`);
  });
  const test = useMutation(async (condition: unknown) =>
    api.post<RuleTestResponse>("/detection-rules/test", { condition, sampleSize: 500 }),
  );
  const runAll = useMutation(async () => api.post<RuleRunResponse>("/detection-rules/run-all"));

  function parseCondition(): unknown | null {
    try {
      return JSON.parse(conditionText);
    } catch (err) {
      setFormError(`Condition is not valid JSON: ${err instanceof Error ? err.message : "parse error"}`);
      return null;
    }
  }

  function resetForm() {
    setShowForm(false);
    setEditingId(null);
    setName("");
    setDescription("");
    setSeverity("medium");
    setConditionText(EXAMPLES[0].condition);
    setWindowMinutes("");
    setTestResult(null);
    setFormError(null);
  }

  function startEdit(rule: DetectionRuleOut) {
    setEditingId(rule.id);
    setShowForm(true);
    setName(rule.name);
    setDescription(rule.description);
    setSeverity(rule.severity);
    setConditionText(JSON.stringify(rule.condition, null, 2));
    setWindowMinutes(rule.evaluationWindowMinutes ? String(rule.evaluationWindowMinutes) : "");
    setTestResult(null);
    setFormError(null);
  }

  async function handleSave() {
    setFormError(null);
    const condition = parseCondition();
    if (condition === null) return;
    const body: Record<string, unknown> = { name, description, condition, severity };
    if (windowMinutes) body.evaluationWindowMinutes = Number(windowMinutes);
    const saved = await save.run(body, editingId);
    if (saved) {
      resetForm();
      rulesQuery.reload();
      coverageQuery.reload();
    }
  }

  const rules = rulesQuery.data ?? [];
  const coverage = coverageQuery.data;

  return (
    <div>
      <PageHeader
        title="Detection rules"
        description="Rules are evaluated against every ingested batch in real time, and can also be run on demand across a bounded window of recent telemetry."
        actions={
          <>
            {canEdit && (
              <Button
                variant="secondary"
                disabled={runAll.isPending}
                onClick={async () => {
                  const result = await runAll.run();
                  if (result) {
                    setRunResult(`Run complete: ${result.alertsCreated} new alert(s).`);
                    rulesQuery.reload();
                    coverageQuery.reload();
                  }
                }}
              >
                Run all rules now
              </Button>
            )}
            {canEdit && (
              <Button onClick={() => (showForm ? resetForm() : setShowForm(true))}>
                {showForm ? "Cancel" : "New rule"}
              </Button>
            )}
          </>
        }
      />

      {runResult && <SuccessBanner message={runResult} />}
      {runAll.error && <ErrorBanner message={runAll.error} />}
      {remove.error && <ErrorBanner message={remove.error} />}
      {toggle.error && <ErrorBanner message={toggle.error} />}

      {coverage && coverage.totalRules > 0 && (
        <Card className="mb-4">
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <span>
              <strong>{coverage.enabledRules}</strong> of {coverage.totalRules} enabled
            </span>
            <span className="text-slate-500">{coverage.rulesWithMatches} have ever matched</span>
            {coverage.neverMatchedRules.length > 0 && (
              <span className="text-amber-700">
                {coverage.neverMatchedRules.length} have never matched -- either mis-authored, or covering a threat
                this tenant has not seen
              </span>
            )}
          </div>
        </Card>
      )}

      {showForm && canEdit && (
        <Card className="mb-5">
          <p className="mb-3 text-sm font-semibold text-slate-700">
            {editingId ? "Edit rule" : "New detection rule"}
          </p>
          {(formError || save.error) && <ErrorBanner message={formError ?? save.error ?? ""} />}
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
              <Field label="Severity of resulting alerts">
                <select className={inputClass} value={severity} onChange={(e) => setSeverity(e.target.value)}>
                  {["informational", "low", "medium", "high", "critical"].map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="Evaluation window (minutes)"
                hint="Bounds an on-demand run. Blank uses the deployment default."
              >
                <input
                  className={inputClass}
                  type="number"
                  min={1}
                  value={windowMinutes}
                  onChange={(e) => setWindowMinutes(e.target.value)}
                  placeholder="10080"
                />
              </Field>
            </div>
            <div className="space-y-3">
              <Field
                label="Condition (JSON)"
                hint="Operators: eq, neq, contains, icontains, in, not_in, gt, gte, lt, lte, regex, exists, cidr. Compose with all/any/not. Add a window for thresholds."
              >
                <textarea
                  className={`${inputClass} font-mono`}
                  rows={12}
                  value={conditionText}
                  onChange={(e) => setConditionText(e.target.value)}
                  spellCheck={false}
                />
              </Field>
              <div className="flex flex-wrap gap-2">
                {EXAMPLES.map((example) => (
                  <button
                    key={example.label}
                    type="button"
                    onClick={() => setConditionText(example.condition)}
                    className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-600 hover:bg-slate-50"
                  >
                    {example.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Button onClick={handleSave} disabled={save.isPending || !name}>
              {editingId ? "Save changes" : "Create rule"}
            </Button>
            <Button
              variant="secondary"
              disabled={test.isPending}
              onClick={async () => {
                setFormError(null);
                const condition = parseCondition();
                if (condition === null) return;
                const result = await test.run(condition);
                if (result) setTestResult(result);
              }}
            >
              Dry run against recent events
            </Button>
            <Button variant="secondary" onClick={resetForm}>
              Cancel
            </Button>
          </div>

          {test.error && <ErrorBanner message={test.error} />}
          {testResult && (
            <div className="mt-3 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-sm">
              Matched <strong>{testResult.matched}</strong> of {testResult.sampled} sampled event(s).
              {testResult.matched === 0 && (
                <span className="ml-1 text-slate-500">
                  Nothing matched -- check the field names against an event on the Telemetry page.
                </span>
              )}
            </div>
          )}
        </Card>
      )}

      {rulesQuery.error && <ErrorBanner message={rulesQuery.error} />}

      {rulesQuery.isLoading ? (
        <Spinner label="Loading rules..." />
      ) : rules.length === 0 ? (
        <EmptyState
          title="No detection rules yet"
          hint="Without at least one enabled rule, ingested telemetry is stored but never produces an alert."
        />
      ) : (
        <Table
          head={
            <tr>
              <Th>Name</Th>
              <Th>Severity</Th>
              <Th>Enabled</Th>
              <Th>Matches</Th>
              <Th>Last matched</Th>
              <Th>Last evaluated</Th>
              <Th />
            </tr>
          }
        >
          {rules.map((rule) => (
            <tr key={rule.id} className="hover:bg-slate-50">
              <Td>
                <p className="font-medium text-slate-800">{rule.name}</p>
                {rule.description && <p className="text-xs text-slate-500">{rule.description}</p>}
                <code className="mt-1 block max-w-md overflow-hidden text-ellipsis whitespace-nowrap text-xs text-slate-400">
                  {JSON.stringify(rule.condition)}
                </code>
              </Td>
              <Td>
                <SeverityBadge severity={rule.severity} />
              </Td>
              <Td>
                <Pill tone={rule.isEnabled ? "green" : "slate"}>{rule.isEnabled ? "enabled" : "disabled"}</Pill>
              </Td>
              <Td>{rule.matchCount}</Td>
              <Td>
                <TimeAgo value={rule.lastMatchedAt} />
              </Td>
              <Td>
                <TimeAgo value={rule.lastEvaluatedAt} />
              </Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  {canEdit && (
                    <>
                      <Button variant="secondary" onClick={() => startEdit(rule)}>
                        Edit
                      </Button>
                      <Button
                        variant="secondary"
                        disabled={toggle.isPending}
                        onClick={async () => {
                          await toggle.run(rule);
                          rulesQuery.reload();
                        }}
                      >
                        {rule.isEnabled ? "Disable" : "Enable"}
                      </Button>
                    </>
                  )}
                  {canDelete && (
                    <Button
                      variant="danger"
                      disabled={remove.isPending}
                      onClick={async () => {
                        if (!window.confirm(`Delete rule "${rule.name}"? Alerts it already raised are kept.`)) return;
                        await remove.run(rule.id);
                        rulesQuery.reload();
                        coverageQuery.reload();
                      }}
                    >
                      Delete
                    </Button>
                  )}
                </div>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}

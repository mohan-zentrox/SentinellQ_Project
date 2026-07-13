import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, ApiError } from "../../api/client";
import type { CaseOut, CaseTimelineEntryOut } from "../../api/types";

const TRANSITIONS: Record<string, string[]> = {
  new: ["investigating"],
  investigating: ["resolved", "escalated"],
  escalated: ["investigating", "resolved"],
  resolved: [],
};

export default function CaseDetail() {
  const { caseId } = useParams<{ caseId: string }>();
  const [caseData, setCaseData] = useState<CaseOut | null>(null);
  const [timeline, setTimeline] = useState<CaseTimelineEntryOut[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!caseId) return;
    try {
      const [c, t] = await Promise.all([
        api.get<CaseOut>(`/cases/${caseId}`),
        api.get<CaseTimelineEntryOut[]>(`/cases/${caseId}/timeline`),
      ]);
      setCaseData(c);
      setTimeline(t);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load case");
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  async function transitionTo(status: string) {
    if (!caseId) return;
    setError(null);
    try {
      // FM6: server enforces the new -> investigating -> resolved/escalated
      // state machine; invalid transitions come back as 409 and are surfaced
      // here rather than allowed client-side.
      const updated = await api.patch<CaseOut>(`/cases/${caseId}/status`, { status });
      setCaseData(updated);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Status transition failed");
    }
  }

  if (!caseData) {
    return <p className="text-sm text-slate-500">{error ?? "Loading case..."}</p>;
  }

  const availableTransitions = TRANSITIONS[caseData.status] ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-slate-900">{caseData.title}</h1>
        <p className="text-sm text-slate-500">{caseData.description || "No description."}</p>
      </div>

      <div className="flex items-center gap-3">
        <span className="rounded-full bg-brand-50 px-3 py-1 text-xs font-medium capitalize text-brand-700">
          {caseData.status}
        </span>
        {availableTransitions.map((status) => (
          <button
            key={status}
            onClick={() => transitionTo(status)}
            className="rounded-md border border-slate-300 px-3 py-1.5 text-xs font-medium capitalize text-slate-700 hover:bg-slate-100"
          >
            Move to {status}
          </button>
        ))}
      </div>

      {error && <p className="text-sm text-severity-critical">{error}</p>}

      <div>
        <h2 className="text-sm font-semibold text-slate-700">Timeline</h2>
        <ol className="mt-2 space-y-2 border-l border-slate-200 pl-4">
          {timeline.map((entry) => (
            <li key={entry.id} className="text-sm">
              <div className="text-slate-800">{entry.message}</div>
              <div className="text-xs text-slate-400">
                {entry.entryType} &middot; {new Date(entry.createdAt).toLocaleString()}
              </div>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

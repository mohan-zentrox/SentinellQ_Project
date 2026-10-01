/**
 * FM6: alert detail -- the triage screen.
 *
 * Shows the contributing events and their threat-intel enrichment inline (the
 * API returns them with the alert), so an analyst can judge the finding without
 * opening a second tab per event.
 */
import { useParams } from "react-router-dom";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import SeverityBadge from "../../components/SeverityBadge";
import {
  Button,
  Card,
  ErrorBanner,
  PageHeader,
  Pill,
  Spinner,
  StatusPill,
  Table,
  Td,
  Th,
  TimeAgo,
} from "../../components/ui";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type { AlertDetailOut, CaseOut } from "../../api/types";

export default function AlertDetail() {
  const { alertId = "" } = useParams();
  const navigate = useNavigate();
  const canTriage = useAuthStore((state) => state.hasRole("analyst"));

  const query = useApiData(() => api.get<AlertDetailOut>(`/alerts/${alertId}`), [alertId]);
  const triage = useMutation(async (status: "open" | "dismissed", reason?: string) => {
    await api.patch(`/alerts/${alertId}`, { status, reason });
  });
  const promote = useMutation(async (title: string) => api.post<CaseOut>("/alerts/promote", { alertIds: [alertId], title }));

  if (query.isLoading) return <Spinner label="Loading alert..." />;
  if (query.error) return <ErrorBanner message={query.error} />;
  const alert = query.data;
  if (!alert) return <ErrorBanner message="Alert not found" />;

  return (
    <div>
      <PageHeader
        title={alert.title}
        description={alert.description}
        actions={
          <>
            <Button variant="secondary" onClick={() => navigate("/alerts")}>
              Back to alerts
            </Button>
            {canTriage && alert.status === "open" && (
              <>
                <Button
                  onClick={async () => {
                    const title = window.prompt("Case title", alert.title);
                    if (!title) return;
                    const created = await promote.run(title);
                    if (created) navigate(`/cases/${created.id}`);
                  }}
                  disabled={promote.isPending}
                >
                  Promote to case
                </Button>
                <Button
                  variant="secondary"
                  disabled={triage.isPending}
                  onClick={async () => {
                    const reason = window.prompt("Why is this a false positive?", "");
                    if (reason === null) return;
                    await triage.run("dismissed", reason);
                    query.reload();
                  }}
                >
                  Dismiss
                </Button>
              </>
            )}
            {canTriage && alert.status === "dismissed" && (
              <Button
                variant="secondary"
                disabled={triage.isPending}
                onClick={async () => {
                  await triage.run("open");
                  query.reload();
                }}
              >
                Reopen
              </Button>
            )}
          </>
        }
      />

      {(triage.error || promote.error) && <ErrorBanner message={triage.error ?? promote.error ?? ""} />}

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Severity</p>
          <div className="mt-1">
            <SeverityBadge severity={alert.severity} />
          </div>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Status</p>
          <div className="mt-1">
            <StatusPill status={alert.status} />
          </div>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Detection</p>
          <div className="mt-1 flex items-center gap-2">
            <Pill tone={alert.detectionSource === "ml" ? "purple" : "slate"}>{alert.detectionSource}</Pill>
            {alert.mlModelVersion && <span className="text-xs text-slate-400">{alert.mlModelVersion}</span>}
          </div>
        </Card>
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-500">Notified</p>
          <p className="mt-1 text-sm">
            <TimeAgo value={alert.notifiedAt} />
          </p>
        </Card>
      </div>

      {alert.caseId && (
        <Card className="mb-5">
          <p className="text-sm">
            Promoted to case{" "}
            <button
              type="button"
              onClick={() => navigate(`/cases/${alert.caseId}`)}
              className="font-medium text-brand-700 hover:underline"
            >
              {alert.caseId}
            </button>
          </p>
        </Card>
      )}

      <h2 className="mb-2 text-sm font-semibold text-slate-700">
        Contributing events ({alert.events.length}
        {alert.eventIds.length > alert.events.length && ` of ${alert.eventIds.length}`})
      </h2>
      {alert.events.length === 0 ? (
        <Card>
          <p className="text-sm text-slate-500">No contributing events are available.</p>
        </Card>
      ) : (
        <Table
          head={
            <tr>
              <Th>Occurred</Th>
              <Th>Category / action</Th>
              <Th>Actor</Th>
              <Th>Source IP</Th>
              <Th>Threat intel</Th>
            </tr>
          }
        >
          {alert.events.map((event) => (
            <tr key={event.id}>
              <Td>
                <TimeAgo value={event.occurredAt} />
              </Td>
              <Td>
                <span className="text-slate-500">{event.eventCategory}</span> / {event.eventAction}
              </Td>
              <Td>{event.actor ?? "--"}</Td>
              <Td className="font-mono text-xs">{event.sourceIp ?? "--"}</Td>
              <Td>
                {event.enrichment?.matched ? (
                  <div className="space-y-1">
                    <Pill tone="red">{event.enrichment.indicatorCount} indicator(s)</Pill>
                    <p className="text-xs text-slate-500">
                      confidence {event.enrichment.maxConfidence}
                      {event.enrichment.tags.length > 0 && ` - ${event.enrichment.tags.join(", ")}`}
                    </p>
                  </div>
                ) : (
                  <span className="text-xs text-slate-400">
                    {event.enrichment ? "no match" : "not enriched"}
                  </span>
                )}
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}

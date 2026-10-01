/**
 * FM9: compliance reporting.
 *
 * Downloads use the server's signed, expiring URL rather than a plain link: a
 * report contains the tenant's security findings, so a permanent unauthenticated
 * link would be a data-leak vector. The expiry is shown so a stale link is
 * explicable rather than mysterious.
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
  StatusPill,
  Table,
  Td,
  Th,
  TimeAgo,
  inputClass,
} from "../../components/ui";
import { useApiData, useMutation } from "../../hooks/useApi";
import { useAuthStore } from "../../store/authStore";
import type { ReportListResponse, ReportOut, ReportTemplateOut } from "../../api/types";

const PAGE_SIZE = 25;

export default function Reports() {
  const canGenerate = useAuthStore((state) => state.hasRole("analyst"));
  const canDelete = useAuthStore((state) => state.hasRole("admin"));

  const [page, setPage] = useState(1);
  const [template, setTemplate] = useState("control_evidence");
  const [format, setFormat] = useState("csv");
  const [days, setDays] = useState("30");

  const templatesQuery = useApiData(() => api.get<ReportTemplateOut[]>("/reports/templates"), []);
  const reportsQuery = useApiData(
    () => api.get<ReportListResponse>(`/reports${queryString({ page, pageSize: PAGE_SIZE })}`),
    [page],
  );

  const generate = useMutation(async () =>
    api.post<ReportOut>("/reports", { template, reportFormat: format, days: Number(days) }),
  );
  const remove = useMutation(async (reportId: string) => api.delete(`/reports/${reportId}`));

  const reports = reportsQuery.data?.items ?? [];
  const templates = templatesQuery.data ?? [];
  const selectedTemplate = templates.find((entry) => entry.name === template);

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Point-in-time exports built from the same aggregations the dashboard uses, so a report and the dashboard can never disagree about the same period."
      />

      {(generate.error || remove.error) && <ErrorBanner message={generate.error ?? remove.error ?? ""} />}

      {canGenerate && (
        <Card className="mb-5">
          <p className="mb-3 text-sm font-semibold text-slate-700">Generate a report</p>
          <div className="grid gap-3 sm:grid-cols-4">
            <Field label="Template">
              <select className={inputClass} value={template} onChange={(e) => setTemplate(e.target.value)}>
                {templates.map((entry) => (
                  <option key={entry.name} value={entry.name}>
                    {entry.name.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Format">
              <select className={inputClass} value={format} onChange={(e) => setFormat(e.target.value)}>
                {(selectedTemplate?.formats ?? ["csv", "json", "html"]).map((value) => (
                  <option key={value} value={value}>
                    {value.toUpperCase()}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Period (days)">
              <input
                className={inputClass}
                type="number"
                min={1}
                max={366}
                value={days}
                onChange={(e) => setDays(e.target.value)}
              />
            </Field>
            <div className="flex items-end">
              <Button
                disabled={generate.isPending}
                onClick={async () => {
                  const created = await generate.run();
                  if (created) reportsQuery.reload();
                }}
              >
                Generate
              </Button>
            </div>
          </div>
          {selectedTemplate && <p className="mt-2 text-xs text-slate-500">{selectedTemplate.description}</p>}
          <p className="mt-2 text-xs text-slate-400">
            HTML reports are printable to PDF from the browser. A native PDF renderer is not included -- it would add a
            large native dependency for an equivalent artifact.
          </p>
        </Card>
      )}

      {reportsQuery.error && <ErrorBanner message={reportsQuery.error} />}

      {reportsQuery.isLoading ? (
        <Spinner label="Loading reports..." />
      ) : reports.length === 0 ? (
        <EmptyState title="No reports yet" hint="Generate one above. Control evidence is a good starting point." />
      ) : (
        <>
          <Table
            head={
              <tr>
                <Th>Template</Th>
                <Th>Format</Th>
                <Th>Status</Th>
                <Th>Period</Th>
                <Th>Rows</Th>
                <Th>Generated</Th>
                <Th />
              </tr>
            }
          >
            {reports.map((report) => (
              <tr key={report.id}>
                <Td className="font-medium text-slate-800">{report.template.replace(/_/g, " ")}</Td>
                <Td>
                  <Pill>{report.reportFormat.toUpperCase()}</Pill>
                </Td>
                <Td>
                  <StatusPill status={report.status} />
                  {report.error && <p className="mt-1 text-xs text-red-600">{report.error}</p>}
                </Td>
                <Td className="text-xs text-slate-500">
                  {new Date(report.periodStart).toLocaleDateString()} to{" "}
                  {new Date(report.periodEnd).toLocaleDateString()}
                </Td>
                <Td>{report.rowCount ?? "--"}</Td>
                <Td>
                  <TimeAgo value={report.generatedAt} />
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {report.downloadUrl && (
                      <a
                        href={api.absoluteUrl(report.downloadUrl)}
                        className="rounded bg-brand-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-700"
                        // The signed link expires; the title makes that visible
                        // rather than leaving a later 404 unexplained.
                        title={
                          report.downloadExpiresAt
                            ? `Link expires ${new Date(report.downloadExpiresAt).toLocaleString()}`
                            : undefined
                        }
                      >
                        Download
                      </a>
                    )}
                    {canDelete && (
                      <Button
                        variant="danger"
                        disabled={remove.isPending}
                        onClick={async () => {
                          if (!window.confirm("Delete this report and its artifact?")) return;
                          await remove.run(report.id);
                          reportsQuery.reload();
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
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={reportsQuery.data?.total ?? 0}
            onPageChange={setPage}
          />
        </>
      )}
    </div>
  );
}

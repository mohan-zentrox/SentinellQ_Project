/**
 * Shared presentational primitives.
 *
 * Extracted because the new pages (events, cases, rules, intel, playbooks,
 * reports, users, settings) would otherwise each re-implement the same table
 * shell, empty state, error banner and pagination -- and drift apart as they did.
 */
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { relativeTime } from "../lib/format";

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-slate-500">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-slate-200 bg-white p-4 shadow-sm ${className}`}>{children}</div>
  );
}

export function StatTile({
  label,
  value,
  hint,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
}) {
  return (
    <Card>
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-900">{value}</p>
      {hint && <p className="mt-1 text-xs text-slate-400">{hint}</p>}
    </Card>
  );
}

export function ErrorBanner({ message, onDismiss }: { message: string; onDismiss?: () => void }) {
  return (
    <div
      role="alert"
      className="mb-4 flex items-start justify-between gap-3 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700"
    >
      <span>{message}</span>
      {onDismiss && (
        <button type="button" onClick={onDismiss} className="text-red-500 hover:text-red-700">
          Dismiss
        </button>
      )}
    </div>
  );
}

export function SuccessBanner({ message }: { message: string }) {
  return (
    <div
      role="status"
      className="mb-4 rounded border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800"
    >
      {message}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white px-4 py-10 text-center">
      <p className="text-sm font-medium text-slate-600">{title}</p>
      {hint && <p className="mt-1 text-sm text-slate-400">{hint}</p>}
    </div>
  );
}

export function Spinner({ label = "Loading..." }: { label?: string }) {
  return (
    <p role="status" className="py-6 text-sm text-slate-500">
      {label}
    </p>
  );
}

export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    // Wide tables scroll inside their own container rather than making the page
    // scroll horizontally.
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500">{head}</thead>
        <tbody className="divide-y divide-slate-100">{children}</tbody>
      </table>
    </div>
  );
}

export function Th({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return <th className={`px-3 py-2 font-medium ${className}`}>{children}</th>;
}

export function Td({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return <td className={`px-3 py-2 align-top text-slate-700 ${className}`}>{children}</td>;
}

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}) {
  const lastPage = Math.max(1, Math.ceil(total / pageSize));
  if (total === 0) return null;
  const first = (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);

  return (
    <div className="mt-3 flex items-center justify-between text-sm text-slate-500">
      <span>
        {first}-{last} of {total}
      </span>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          className="rounded border border-slate-300 px-2 py-1 disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= lastPage}
          className="rounded border border-slate-300 px-2 py-1 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

export function Button({
  children,
  variant = "primary",
  type = "button",
  ...rest
}: {
  children: ReactNode;
  variant?: "primary" | "secondary" | "danger";
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const styles = {
    primary: "bg-brand-600 text-white hover:bg-brand-700 disabled:bg-brand-300",
    secondary: "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50",
    danger: "border border-red-300 bg-white text-red-700 hover:bg-red-50",
  }[variant];
  return (
    <button
      type={type}
      className={`rounded px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60 ${styles}`}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="block text-sm">
      <span className="font-medium text-slate-700">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-400">{hint}</span>}
    </label>
  );
}

export const inputClass =
  "mt-1 w-full rounded border border-slate-300 px-2 py-1.5 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500";

export function Pill({ children, tone = "slate" }: { children: ReactNode; tone?: string }) {
  const tones: Record<string, string> = {
    slate: "bg-slate-100 text-slate-700",
    green: "bg-emerald-100 text-emerald-800",
    amber: "bg-amber-100 text-amber-800",
    red: "bg-red-100 text-red-800",
    blue: "bg-blue-100 text-blue-800",
    purple: "bg-purple-100 text-purple-800",
  };
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${tones[tone] ?? tones.slate}`}>
      {children}
    </span>
  );
}

const STATUS_TONES: Record<string, string> = {
  open: "amber",
  dismissed: "slate",
  promoted: "blue",
  new: "amber",
  investigating: "blue",
  escalated: "red",
  resolved: "green",
  active: "green",
  pending: "amber",
  canceled: "slate",
  succeeded: "green",
  failed: "red",
  partial: "amber",
  pending_approval: "purple",
  rejected: "slate",
  running: "blue",
  skipped: "slate",
  ready: "green",
  queued: "amber",
  generating: "blue",
  sent: "green",
  suppressed: "slate",
  dry_run: "purple",
};

export function StatusPill({ status }: { status: string }) {
  return <Pill tone={STATUS_TONES[status] ?? "slate"}>{status.replace(/_/g, " ")}</Pill>;
}

/** Relative time for recency, with the absolute value in the tooltip. */
export function TimeAgo({ value }: { value: string | null }) {
  if (!value) return <span className="text-slate-400">never</span>;
  return (
    <time dateTime={value} title={new Date(value).toLocaleString()} className="text-slate-500">
      {relativeTime(value)}
    </time>
  );
}

export function CaseLink({ caseId }: { caseId: string }) {
  return (
    <Link to={`/cases/${caseId}`} className="text-brand-700 hover:underline">
      {caseId}
    </Link>
  );
}


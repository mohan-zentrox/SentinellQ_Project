const COLORS: Record<string, string> = {
  informational: "bg-severity-informational/10 text-severity-informational",
  low: "bg-severity-low/10 text-severity-low",
  medium: "bg-severity-medium/10 text-severity-medium",
  high: "bg-severity-high/10 text-severity-high",
  critical: "bg-severity-critical/10 text-severity-critical",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const classes = COLORS[severity] ?? "bg-slate-100 text-slate-600";
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize ${classes}`}>
      {severity}
    </span>
  );
}

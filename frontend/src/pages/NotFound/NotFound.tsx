import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-white px-4 py-12 text-center">
      <p className="text-lg font-semibold text-slate-700">Page not found</p>
      <p className="mt-1 text-sm text-slate-500">
        That route does not exist in SentinelIQ.
      </p>
      <Link to="/alerts" className="mt-4 inline-block text-sm font-medium text-brand-700 hover:underline">
        Back to alerts
      </Link>
    </div>
  );
}

import { FormEvent, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, ApiError } from "../../api/client";
import { useAuthStore } from "../../store/authStore";
import type { TokenResponse } from "../../api/types";

export default function Signup() {
  const navigate = useNavigate();
  const setSession = useAuthStore((state) => state.setSession);
  const [companyName, setCompanyName] = useState("");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      // FM1: tenant signup creates a Tenant + Owner user in one call.
      const token = await api.post<TokenResponse>("/auth/signup", {
        companyName,
        fullName,
        email,
        password,
      });
      setSession(token);
      navigate("/alerts");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Signup failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <div className="w-full max-w-md rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
        <h1 className="text-xl font-semibold text-brand-700">Create your SentinelIQ tenant</h1>
        <p className="mt-1 text-sm text-slate-500">
          You'll be the Owner of this organization's workspace.
        </p>
        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <Field label="Company / organization name" value={companyName} onChange={setCompanyName} required />
          <Field label="Your full name" value={fullName} onChange={setFullName} />
          <Field label="Work email" type="email" value={email} onChange={setEmail} required />
          <Field label="Password" type="password" value={password} onChange={setPassword} required minLength={8} />
          {error && <p className="text-sm text-severity-critical">{error}</p>}
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded-md bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700 disabled:opacity-50"
          >
            {isSubmitting ? "Creating tenant..." : "Create tenant"}
          </button>
        </form>
        <p className="mt-4 text-sm text-slate-500">
          Already have a tenant?{" "}
          <Link to="/login" className="text-brand-600 hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}

function Field(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  required?: boolean;
  minLength?: number;
}) {
  const { label, value, onChange, type = "text", required, minLength } = props;
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium text-slate-700">{label}</span>
      <input
        type={type}
        value={value}
        required={required}
        minLength={minLength}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
      />
    </label>
  );
}

/**
 * FM1/FM11: user and RBAC administration.
 *
 * Every guard the API enforces is also reflected here -- you cannot change your
 * own role, cannot deactivate yourself, and an admin cannot grant or reset an
 * owner. The controls are hidden rather than shown-and-rejected because a button
 * that always 403s is worse than no button; the server remains the authority.
 */
import { useState } from "react";
import { api } from "../../api/client";
import {
  Button,
  Card,
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
import type { Role, UserOut } from "../../api/types";

const ROLES: Role[] = ["owner", "admin", "analyst", "viewer"];

const ROLE_DESCRIPTIONS: Record<Role, string> = {
  owner: "Full control, including billing and SSO.",
  admin: "Manage rules, playbooks, users and intel. No billing.",
  analyst: "Investigate alerts and cases, author rules and indicators.",
  viewer: "Read-only.",
};

export default function Users() {
  const myUserId = useAuthStore((state) => state.userId);
  const myRole = useAuthStore((state) => state.role);
  const isOwner = myRole === "owner";

  const usersQuery = useApiData(() => api.get<UserOut[]>("/tenants/me/users"), []);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [role, setRole] = useState<Role>("analyst");
  const [notice, setNotice] = useState<string | null>(null);

  const createUser = useMutation(async () =>
    api.post<UserOut>("/tenants/me/users", { email, password, fullName, role }),
  );
  const updateUser = useMutation(async (userId: string, body: Record<string, unknown>) =>
    api.patch<UserOut>(`/tenants/me/users/${userId}`, body),
  );
  const resetPassword = useMutation(async (userId: string, newPassword: string) =>
    api.post(`/tenants/me/users/${userId}/reset-password`, { newPassword }),
  );

  const users = usersQuery.data ?? [];
  const activeOwners = users.filter((user) => user.role === "owner" && user.isActive).length;
  const actionError = createUser.error ?? updateUser.error ?? resetPassword.error;

  return (
    <div>
      <PageHeader title="Users" description="Tenant members and their roles. Deactivating a user ends their sessions immediately." />

      {notice && <SuccessBanner message={notice} />}
      {actionError && <ErrorBanner message={actionError} />}

      <Card className="mb-5">
        <p className="mb-3 text-sm font-semibold text-slate-700">Invite a user</p>
        <form
          className="grid gap-3 sm:grid-cols-4"
          onSubmit={async (e) => {
            e.preventDefault();
            const created = await createUser.run();
            if (created) {
              setNotice(`${created.email} added as ${created.role}.`);
              setEmail("");
              setPassword("");
              setFullName("");
              usersQuery.reload();
            }
          }}
        >
          <Field label="Email">
            <input
              className={inputClass}
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>
          <Field label="Full name">
            <input className={inputClass} value={fullName} onChange={(e) => setFullName(e.target.value)} />
          </Field>
          <Field label="Initial password" hint="At least 8 characters. They should change it after first sign-in.">
            <input
              className={inputClass}
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
          <Field label="Role">
            <select className={inputClass} value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {ROLES.filter((value) => value !== "owner" || isOwner).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </Field>
          <div className="sm:col-span-4">
            <Button type="submit" disabled={createUser.isPending}>
              Add user
            </Button>
            <span className="ml-3 text-xs text-slate-500">{ROLE_DESCRIPTIONS[role]}</span>
          </div>
        </form>
      </Card>

      {usersQuery.error && <ErrorBanner message={usersQuery.error} />}

      {usersQuery.isLoading ? (
        <Spinner label="Loading users..." />
      ) : (
        <Table
          head={
            <tr>
              <Th>Email</Th>
              <Th>Name</Th>
              <Th>Role</Th>
              <Th>Status</Th>
              <Th>Source</Th>
              <Th>Last sign-in</Th>
              <Th />
            </tr>
          }
        >
          {users.map((user) => {
            const isSelf = user.id === myUserId;
            // Mirrors the API's guards so the UI does not offer actions the
            // server will refuse.
            const canChangeRole = !isSelf && (isOwner || user.role !== "owner");
            const isLastOwner = user.role === "owner" && activeOwners <= 1;
            const canDeactivate = !isSelf && !isLastOwner && (isOwner || user.role !== "owner");
            const canReset = isOwner || user.role !== "owner";

            return (
              <tr key={user.id}>
                <Td className="font-medium text-slate-800">
                  {user.email}
                  {isSelf && <span className="ml-1 text-xs text-slate-400">(you)</span>}
                </Td>
                <Td>{user.fullName || "--"}</Td>
                <Td>
                  {canChangeRole ? (
                    <select
                      className="rounded border border-slate-300 px-1 py-0.5 text-sm"
                      value={user.role}
                      onChange={async (e) => {
                        const updated = await updateUser.run(user.id, { role: e.target.value });
                        if (updated) {
                          setNotice(`${user.email} is now ${updated.role}.`);
                          usersQuery.reload();
                        }
                      }}
                    >
                      {ROLES.filter((value) => value !== "owner" || isOwner).map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <Pill>{user.role}</Pill>
                  )}
                </Td>
                <Td>
                  <Pill tone={user.isActive ? "green" : "slate"}>{user.isActive ? "active" : "deactivated"}</Pill>
                  {isLastOwner && <p className="mt-1 text-xs text-slate-400">last active owner</p>}
                </Td>
                <Td className="text-xs text-slate-500">{user.provisionedBy}</Td>
                <Td>
                  <TimeAgo value={user.lastLoginAt} />
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {canReset && (
                      <Button
                        variant="secondary"
                        disabled={resetPassword.isPending}
                        onClick={async () => {
                          const newPassword = window.prompt(
                            `Set a new password for ${user.email}. This ends their active sessions.`,
                          );
                          if (!newPassword) return;
                          await resetPassword.run(user.id, newPassword);
                          setNotice(`Password reset for ${user.email}; their sessions were ended.`);
                        }}
                      >
                        Reset password
                      </Button>
                    )}
                    {canDeactivate && user.isActive && (
                      <Button
                        variant="danger"
                        disabled={updateUser.isPending}
                        onClick={async () => {
                          if (!window.confirm(`Deactivate ${user.email}? They lose access immediately.`)) return;
                          await updateUser.run(user.id, { isActive: false });
                          setNotice(`${user.email} deactivated.`);
                          usersQuery.reload();
                        }}
                      >
                        Deactivate
                      </Button>
                    )}
                    {!user.isActive && (
                      <Button
                        variant="secondary"
                        disabled={updateUser.isPending}
                        onClick={async () => {
                          await updateUser.run(user.id, { isActive: true });
                          setNotice(`${user.email} reactivated.`);
                          usersQuery.reload();
                        }}
                      >
                        Reactivate
                      </Button>
                    )}
                  </div>
                </Td>
              </tr>
            );
          })}
        </Table>
      )}
    </div>
  );
}

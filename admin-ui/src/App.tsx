import { useCallback, useEffect, useState } from "react";
import * as api from "./api";
import type { Activation } from "./api";

const MESSAGES: Record<string, string> = {
  unauthorized: "Session expired or invalid. Please sign in again.",
  invalid_password: "Password format is invalid (32 printable characters expected).",
  admin_not_configured: "Admin authentication is not configured on the server.",
  activation_store_not_configured: "The activation store is not configured on the server.",
  origin_mismatch: "Request rejected: origin mismatch.",
  store_write_failed: "The server could not write the activation store.",
  store_commit_uncertain:
    "The server could not confirm whether the change was saved. The list was refreshed - check the activation status before trying again.",
  invalid_max_devices: "Max devices must be a whole number from 1 to 100.",
  invalid_expires_in_days: "Validity must be a whole number of days from 1 to 3650.",
  invalid_days: "Days must be a whole number from 1 to 3650.",
  invalid_query: "Invalid search or filter.",
  not_extendable_revoked: "A revoked activation cannot be extended.",
  not_extendable_not_expiring: "This activation never expires, so there is nothing to extend.",
  rate_limited: "Too many requests. Wait a moment and try again.",
  forbidden: "Your role (viewer) does not allow this action.",
  not_found: "Not found.",
};
const msg = (e: unknown) =>
  e instanceof api.ApiError ? (MESSAGES[e.code] ?? `Server error (${e.status} ${e.code})`) : "Cannot reach the API.";

type Auth = "checking" | "out" | "in";

export function App() {
  const [auth, setAuth] = useState<Auth>("checking");

  useEffect(() => {
    if (!api.getCsrf()) return setAuth("out");
    api.status().then(() => setAuth("in"), () => setAuth("out"));
  }, []);

  if (auth === "checking") return <p className="p-8 text-slate-500">Checking session…</p>;
  if (auth === "out") return <Login onDone={() => setAuth("in")} />;
  return <Dashboard onLogout={() => setAuth("out")} />;
}

function Login({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(password);
      onDone();
    } catch (err) {
      setError(msg(err));
    } finally {
      setBusy(false);
      setPassword("");
    }
  };

  return (
    <main className="min-h-screen grid place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm bg-white rounded-xl shadow p-6 space-y-4">
        <h1 className="text-xl font-semibold">VPNrus Admin</h1>
        <label className="block text-sm">
          <span className="text-slate-600">Administrator password</span>
          <input
            type="password" autoComplete="current-password" required value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded border border-slate-300 px-3 py-2"
          />
        </label>
        {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
        <button disabled={busy} className="w-full rounded bg-slate-900 text-white py-2 disabled:opacity-50">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

const PAGE_SIZE = 10;

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [page, setPage] = useState<api.ListResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [sessionOk, setSessionOk] = useState<boolean | null>(null);
  const [role, setRole] = useState<"admin" | "viewer" | null>(null);
  const [gateway, setGateway] = useState<api.GatewayInfo | null>(null);
  const [searchInput, setSearchInput] = useState("");
  const [query, setQuery] = useState<api.ListQuery>({ q: "", status: "", limit: PAGE_SIZE, offset: 0 });
  // One-time credential of a just-created activation. Kept in component
  // state only (never in storage) and dropped on dismiss or sign-out.
  const [issued, setIssued] = useState<{ id: string; credential: string } | null>(null);
  const [newDevices, setNewDevices] = useState("1");
  const [newDays, setNewDays] = useState("30");
  const [extendDays, setExtendDays] = useState("30");

  const fail = useCallback((e: unknown) => {
    if (e instanceof api.ApiError && e.status === 401) onLogout();
    setError(msg(e));
  }, [onLogout]);

  const load = useCallback(() => {
    setError(null);
    api.status().then((s) => { setSessionOk(s.session_exists); setRole(s.role); }, fail);
    api.listActivations(query).then(setPage, fail);
    api.gatewayInfo().then(setGateway, fail);
  }, [fail, query]);

  // Reconcile with the server after a failed mutation without clearing its
  // error; a refresh failure is appended to it, not substituted.
  const refreshAfterFailure = useCallback(async (original: unknown) => {
    try {
      setPage(await api.listActivations(query));
    } catch (refreshErr) {
      if (refreshErr instanceof api.ApiError && refreshErr.status === 401) onLogout();
      setError(`${msg(original)} Refreshing the list also failed: ${msg(refreshErr)}`);
    }
  }, [onLogout, query]);

  useEffect(load, [load]);

  const mutate = async (action: () => Promise<string>) => {
    setNotice(null);
    try {
      setNotice(await action());
      load();
    } catch (e) {
      fail(e);
      if (!(e instanceof api.ApiError && e.status === 401)) await refreshAfterFailure(e);
    }
  };

  const doRevoke = (id: string) => {
    if (!window.confirm(`Revoke activation ${id}? Bound devices lose access. This cannot be undone here.`)) return;
    return mutate(async () => {
      const r = await api.revoke(id);
      return r.status === "revoked" ? "Activation revoked." : "Activation was already revoked.";
    });
  };

  const doCreate = (e: React.FormEvent) => {
    e.preventDefault();
    setIssued(null);
    const days = newDays.trim() === "" ? null : Number(newDays);
    return mutate(async () => {
      const r = await api.createActivation(Number(newDevices), days);
      setIssued({ id: r.activation_id, credential: r.credential });
      return "Activation created. Copy the credential now - it is not shown again.";
    });
  };

  const doExtend = (id: string) =>
    mutate(async () => {
      const r = await api.extendActivation(id, Number(extendDays));
      return `Activation extended. New expiry: ${new Date(r.expires_at).toLocaleString()}.`;
    });

  const doLogout = async () => {
    setIssued(null);
    await api.logout().catch(() => undefined);
    onLogout();
  };

  const applySearch = (e: React.FormEvent) => {
    e.preventDefault();
    setQuery({ ...query, q: searchInput.trim().toLowerCase(), offset: 0 });
  };

  const items = page?.activations ?? null;
  const total = page?.total ?? 0;
  const active = items?.filter((i) => i.entitlement === "ACTIVE").length ?? 0;
  const devices = items?.reduce((n, i) => n + i.devices.length, 0) ?? 0;
  const sel = items?.find((i) => i.activation_id === selected) ?? null;
  const from = total === 0 ? 0 : query.offset + 1;
  const to = query.offset + (items?.length ?? 0);

  return (
    <div className="max-w-5xl mx-auto px-4 py-6 space-y-6">
      <header className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">VPNrus Admin</h1>
        <div className="flex gap-2">
          <button onClick={load} className="rounded border px-3 py-1.5 text-sm">Refresh</button>
          <button onClick={doLogout} className="rounded bg-slate-900 text-white px-3 py-1.5 text-sm">Sign out</button>
        </div>
      </header>

      {error && <p role="alert" className="rounded bg-red-50 text-red-700 px-3 py-2 text-sm">{error}</p>}
      {notice && <p role="status" className="rounded bg-green-50 text-green-700 px-3 py-2 text-sm">{notice}</p>}

      {issued && (
        <section className="rounded-xl border border-amber-300 bg-amber-50 p-4 space-y-2 text-sm">
          <p className="font-medium">New activation credential (shown once)</p>
          <p className="text-slate-600">Activation ID: <span className="font-mono">{issued.id}</span></p>
          <div className="flex gap-2">
            <input
              readOnly value={issued.credential} aria-label="Activation credential"
              className="flex-1 rounded border border-slate-300 bg-white px-2 py-1 font-mono"
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              onClick={() => navigator.clipboard?.writeText(issued.credential).then(() => setNotice("Credential copied."), () => setError("Could not copy - select the text and copy it manually."))}
              className="rounded border px-3 py-1"
            >Copy</button>
            <button onClick={() => setIssued(null)} className="rounded bg-slate-900 text-white px-3 py-1">Done</button>
          </div>
          <p className="text-xs text-slate-600">It cannot be retrieved later. Closing this box discards it.</p>
        </section>
      )}

      <section className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="API session" value={sessionOk === null ? "…" : sessionOk ? `Authenticated${role ? ` (${role})` : ""}` : "Unknown"} />
        <Stat label="Matching activations" value={page ? String(total) : "…"} />
        <Stat label="Active (this page)" value={items ? String(active) : "…"} />
        <Stat label="Bound devices (this page)" value={items ? String(devices) : "…"} />
      </section>

      <section className="bg-white rounded-xl shadow p-4 space-y-2 text-sm">
        <h2 className="font-medium">This gateway</h2>
        {gateway === null ? (
          <p className="text-slate-500">Loading…</p>
        ) : (
          <>
            <p className="text-slate-600">
              <span className="font-mono">{gateway.endpoint.host}:{gateway.endpoint.port}</span>
              {" · "}up {formatUptime(gateway.uptime_seconds)}
              {" · "}manifest {gateway.manifest.present ? "present" : gateway.manifest.configured ? "configured but missing" : "not configured"}
            </p>
            <div className="flex flex-wrap gap-2">
              {Object.entries(gateway.transports).map(([name, on]) => (
                <span key={name} className={`rounded px-2 py-0.5 text-xs ${on ? "bg-green-100 text-green-800" : "bg-slate-200 text-slate-600"}`}>
                  {name.replace(/_/g, " ")}: {on ? "on" : "off"}
                </span>
              ))}
            </div>
            {gateway.activations ? (
              <p className="text-slate-600">
                Activations: {gateway.activations.total} total, {gateway.activations.active} active,{" "}
                {gateway.activations.expired} expired, {gateway.activations.revoked} revoked;{" "}
                {gateway.activations.bound_devices} bound devices.
              </p>
            ) : (
              <p className="text-slate-500">Activation store not configured.</p>
            )}
            <p className="text-xs text-slate-500">
              Shows this API node only. Other gateways and traffic statistics are not available yet.
            </p>
          </>
        )}
      </section>

      {role === "admin" && (
      <section className="bg-white rounded-xl shadow p-4">
        <h2 className="font-medium mb-3">Create activation</h2>
        <form onSubmit={doCreate} className="flex flex-wrap items-end gap-3 text-sm">
          <label className="block">
            <span className="text-slate-600">Max devices (1-100)</span>
            <input type="number" min={1} max={100} required value={newDevices} onChange={(e) => setNewDevices(e.target.value)}
              className="mt-1 w-28 rounded border border-slate-300 px-2 py-1" />
          </label>
          <label className="block">
            <span className="text-slate-600">Valid for days (empty = never expires)</span>
            <input type="number" min={1} max={3650} value={newDays} onChange={(e) => setNewDays(e.target.value)}
              className="mt-1 w-40 rounded border border-slate-300 px-2 py-1" />
          </label>
          <button className="rounded bg-slate-900 text-white px-3 py-1.5">Create</button>
        </form>
      </section>
      )}

      <section className="bg-white rounded-xl shadow overflow-hidden">
        <div className="px-4 py-3 border-b flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-medium">Activations</h2>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <form onSubmit={applySearch} className="flex gap-2">
              <input
                value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="ID (hex)"
                aria-label="Search by activation ID" className="w-36 rounded border border-slate-300 px-2 py-1 font-mono"
              />
              <button className="rounded border px-2 py-1">Search</button>
            </form>
            <select
              aria-label="Filter by status" value={query.status}
              onChange={(e) => setQuery({ ...query, status: e.target.value, offset: 0 })}
              className="rounded border border-slate-300 px-2 py-1"
            >
              <option value="">All</option>
              <option value="ACTIVE">Active</option>
              <option value="EXPIRED">Expired</option>
              <option value="REVOKED">Revoked</option>
            </select>
          </div>
        </div>
        {items === null ? (
          <p className="p-4 text-slate-500">Loading…</p>
        ) : items.length === 0 ? (
          <p className="p-4 text-slate-500">
            {query.q || query.status ? "No activations match the current filter." : "No activations in the store."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-slate-500">
                <tr><th className="px-4 py-2">ID</th><th>Status</th><th>Devices</th><th>Expires</th>{role === "admin" && <th />}</tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.activation_id} className="border-t">
                    <td className="px-4 py-2 font-mono">
                      <button className="underline" onClick={() => setSelected(a.activation_id)}>
                        {a.activation_id.slice(0, 8)}…
                      </button>
                    </td>
                    <td><Badge value={a.entitlement} /></td>
                    <td>{a.devices.length} / {a.max_devices}</td>
                    <td>{a.expires_at ? new Date(a.expires_at).toLocaleDateString() : "never"}</td>
                    {role === "admin" && (
                    <td className="px-4 text-right">
                      <button
                        disabled={a.status === "REVOKED"} onClick={() => doRevoke(a.activation_id)}
                        className="rounded border border-red-300 text-red-700 px-2 py-1 disabled:opacity-40"
                      >Revoke</button>
                    </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {page && total > 0 && (
          <div className="px-4 py-3 border-t flex items-center justify-between text-sm text-slate-600">
            <span>{from}-{to} of {total}</span>
            <div className="flex gap-2">
              <button
                disabled={query.offset === 0}
                onClick={() => setQuery({ ...query, offset: Math.max(0, query.offset - PAGE_SIZE) })}
                className="rounded border px-2 py-1 disabled:opacity-40"
              >Previous</button>
              <button
                disabled={to >= total}
                onClick={() => setQuery({ ...query, offset: query.offset + PAGE_SIZE })}
                className="rounded border px-2 py-1 disabled:opacity-40"
              >Next</button>
            </div>
          </div>
        )}
      </section>

      {sel && (
        <section className="bg-white rounded-xl shadow p-4 space-y-3">
          <div className="flex justify-between">
            <h2 className="font-medium">Activation detail</h2>
            <button onClick={() => setSelected(null)} className="text-sm underline">Close</button>
          </div>
          <dl className="text-sm grid grid-cols-[8rem_1fr] gap-y-1">
            <dt className="text-slate-500">ID</dt><dd className="font-mono break-all">{sel.activation_id}</dd>
            <dt className="text-slate-500">Entitlement</dt><dd><Badge value={sel.entitlement} /></dd>
            <dt className="text-slate-500">Created</dt><dd>{sel.created_at}</dd>
            <dt className="text-slate-500">Expires</dt><dd>{sel.expires_at ?? "never"}</dd>
            <dt className="text-slate-500">Devices</dt>
            <dd>
              {sel.devices.length === 0 ? "No devices bound." : (
                <ul className="space-y-1">
                  {sel.devices.map((d) => (
                    <li key={d.public_key} className="font-mono break-all">{d.public_key} <span className="text-slate-500">({d.state})</span></li>
                  ))}
                </ul>
              )}
            </dd>
          </dl>
          {role === "admin" && (
          <form
            onSubmit={(e) => { e.preventDefault(); void doExtend(sel.activation_id); }}
            className="flex flex-wrap items-end gap-2 text-sm"
          >
            <label className="block">
              <span className="text-slate-600">Extend by days</span>
              <input type="number" min={1} max={3650} required value={extendDays} onChange={(e) => setExtendDays(e.target.value)}
                className="mt-1 w-28 rounded border border-slate-300 px-2 py-1" />
            </label>
            <button
              disabled={sel.status === "REVOKED" || sel.expires_at === null}
              className="rounded border px-3 py-1.5 disabled:opacity-40"
            >Extend</button>
            {sel.expires_at === null && <span className="text-slate-500">Never expires - nothing to extend.</span>}
          </form>
          )}
          <p className="text-xs text-slate-500">
            Not available: unbinding a single device (an issued gateway key would stay valid, so only revoking the
            whole activation is a real cut-off), traffic stats, administrator/viewer roles (one shared admin password).
          </p>
        </section>
      )}
    </div>
  );
}

const formatUptime = (s: number) => {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
};

const Stat = ({ label, value }: { label: string; value: string }) => (
  <div className="bg-white rounded-xl shadow p-3">
    <div className="text-xs text-slate-500">{label}</div>
    <div className="text-lg font-semibold">{value}</div>
  </div>
);

const Badge = ({ value }: { value: string }) => (
  <span className={`rounded px-2 py-0.5 text-xs ${value === "ACTIVE" ? "bg-green-100 text-green-800" : "bg-slate-200 text-slate-700"}`}>
    {value}
  </span>
);

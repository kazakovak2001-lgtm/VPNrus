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
    "The server could not confirm whether the revocation was saved. The list was refreshed - check the activation status before trying again.",
  rate_limited: "Too many requests. Wait a moment and try again.",
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

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [items, setItems] = useState<Activation[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [sessionOk, setSessionOk] = useState<boolean | null>(null);

  const fail = useCallback((e: unknown) => {
    if (e instanceof api.ApiError && e.status === 401) onLogout();
    setError(msg(e));
  }, [onLogout]);

  const load = useCallback(() => {
    setError(null);
    api.status().then((s) => setSessionOk(s.session_exists), fail);
    api.listActivations().then((r) => setItems(r.activations), fail);
  }, [fail]);

  // Reconcile with the server after a failed revoke without clearing the
  // revoke error; a refresh failure is appended to it, not substituted.
  const refreshAfterFailure = useCallback(async (original: unknown) => {
    try {
      setItems((await api.listActivations()).activations);
    } catch (refreshErr) {
      if (refreshErr instanceof api.ApiError && refreshErr.status === 401) onLogout();
      setError(`${msg(original)} Refreshing the list also failed: ${msg(refreshErr)}`);
    }
  }, [onLogout]);

  useEffect(load, [load]);

  const doRevoke = async (id: string) => {
    if (!window.confirm(`Revoke activation ${id}? Bound devices lose access. This cannot be undone here.`)) return;
    try {
      const r = await api.revoke(id);
      setNotice(r.status === "revoked" ? "Activation revoked." : "Activation was already revoked.");
      load();
    } catch (e) {
      fail(e);
      if (!(e instanceof api.ApiError && e.status === 401)) await refreshAfterFailure(e);
    }
  };

  const doLogout = async () => {
    await api.logout().catch(() => undefined);
    onLogout();
  };

  const active = items?.filter((i) => i.entitlement === "ACTIVE").length ?? 0;
  const devices = items?.reduce((n, i) => n + i.devices.length, 0) ?? 0;
  const sel = items?.find((i) => i.activation_id === selected) ?? null;

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

      <section className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="API session" value={sessionOk === null ? "…" : sessionOk ? "Authenticated" : "Unknown"} />
        <Stat label="Activations" value={items ? String(items.length) : "…"} />
        <Stat label="Active" value={items ? String(active) : "…"} />
        <Stat label="Bound devices" value={items ? String(devices) : "…"} />
      </section>

      <section className="bg-white rounded-xl shadow overflow-hidden">
        <h2 className="px-4 py-3 font-medium border-b">Activations</h2>
        {items === null ? (
          <p className="p-4 text-slate-500">Loading…</p>
        ) : items.length === 0 ? (
          <p className="p-4 text-slate-500">No activations in the store.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-slate-500">
                <tr><th className="px-4 py-2">ID</th><th>Status</th><th>Devices</th><th>Expires</th><th /></tr>
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
                    <td className="px-4 text-right">
                      <button
                        disabled={a.status === "REVOKED"} onClick={() => doRevoke(a.activation_id)}
                        className="rounded border border-red-300 text-red-700 px-2 py-1 disabled:opacity-40"
                      >Revoke</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {sel && (
        <section className="bg-white rounded-xl shadow p-4 space-y-2">
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
          <p className="text-xs text-slate-500">
            Not available yet: per-device revocation, traffic stats, administrator/viewer roles
            (a single shared admin password is used).
          </p>
        </section>
      )}
    </div>
  );
}

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

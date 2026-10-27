// Thin client for the pocvpn-api admin endpoints. The session cookie is
// HttpOnly and managed by the browser; only the CSRF token is kept here
// (sessionStorage), because the server returns it exactly once at login.

export interface Device {
  public_key: string;
  state: string;
}

export interface Activation {
  activation_id: string;
  status: string;
  entitlement: string;
  max_devices: number;
  created_at: string;
  expires_at: string | null;
  devices: Device[];
}

export class ApiError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

const CSRF_KEY = "vpnrus-admin-csrf";
export const getCsrf = () => sessionStorage.getItem(CSRF_KEY);
const setCsrf = (v: string | null) =>
  v ? sessionStorage.setItem(CSRF_KEY, v) : sessionStorage.removeItem(CSRF_KEY);

async function call<T>(method: string, path: string, body?: unknown, mutating = false): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (mutating) {
    const csrf = getCsrf();
    if (!csrf) throw new ApiError(401, "unauthorized");
    headers["X-CSRF-Token"] = csrf;
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : mutating ? "" : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string }).error ?? "error");
  return data as T;
}

export async function login(password: string): Promise<void> {
  const r = await call<{ csrf_token: string }>("POST", "/admin/login", { password });
  setCsrf(r.csrf_token);
}

export async function logout(): Promise<void> {
  try {
    await call("POST", "/admin/logout", undefined, true);
  } finally {
    setCsrf(null);
  }
}

export const status = () => call<{ status: string; session_exists: boolean }>("GET", "/admin/status");
export const listActivations = () => call<{ activations: Activation[] }>("GET", "/admin/activations");
export const revoke = (id: string) =>
  call<{ status: string }>("POST", `/admin/activations/${id}/revoke`, undefined, true);

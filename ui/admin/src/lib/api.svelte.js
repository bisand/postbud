// The one place the admin token lives, and the one fetch wrapper.
//
// sessionStorage, not localStorage: the token dies with the tab. An admin
// credential that outlives the session on a shared machine is a worse
// trade than typing it again tomorrow.

let token = $state(sessionStorage.getItem("postbud-admin-token") || "");

export const auth = {
  get token() {
    return token;
  },
  set(value) {
    token = value;
    sessionStorage.setItem("postbud-admin-token", value);
  },
  clear() {
    token = "";
    sessionStorage.removeItem("postbud-admin-token");
  },
};

// Who is signed in, and as what. Display only — the server enforces
// roles in its extractors; hiding a button is courtesy, not security.
let session = $state(null);

export const me = {
  get value() {
    return session;
  },
  set(value) {
    session = value;
  },
  get write() {
    return session?.role === "admin";
  },
};

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function api(path, opts = {}) {
  const headers = { Authorization: `Bearer ${token}`, ...(opts.headers || {}) };
  if (opts.body) headers["Content-Type"] = "application/json";

  const res = await fetch(`/admin/api${path}`, { ...opts, headers });

  if (res.status === 401) {
    // Invalid token: drop it so the app falls back to the login gate,
    // instead of every section failing one by one.
    auth.clear();
    throw new ApiError("Invalid admin token.", 401);
  }
  if (!res.ok) {
    let message;
    try {
      message = (await res.json()).error;
    } catch {
      message = res.statusText;
    }
    throw new ApiError(message, res.status);
  }
  if (res.status === 204) return null;
  const type = res.headers.get("content-type") || "";
  return type.includes("json") ? res.json() : res.text();
}

export function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return d.toLocaleString("sv-SE", { timeZoneName: undefined }).slice(0, 16);
}

// The one place the admin token lives, and the one fetch wrapper.
//
// The token is kept in a module variable and NOWHERE else: not
// localStorage, not sessionStorage. Both are equally open to an XSS —
// same origin, same JavaScript — so what matters is not which store but
// what a break-in is worth, and the only credential reachable from the
// page is now the id_token, over when it expires.
//
// It used to live in sessionStorage so it would die with the tab, on the
// reasoning that an admin credential outliving the session on a shared
// machine was a worse trade than typing it again tomorrow. The trade has
// moved rather than gone: the session itself is now carried by an
// HttpOnly refresh cookie the page cannot read, which DOES survive a
// closed tab — bounded to REFRESH_COOKIE_MAX_AGE in oidc.rs (12 hours,
// so it does not carry overnight) and dropped for good by signing out.
// What a shared machine needs is the sign-out button, not a store that
// forgets.
//
// A consequence worth knowing: the break-glass ADMIN_TOKEN has no cookie
// behind it, so it must be typed again after a reload.

let token = $state("");

export const auth = {
  get token() {
    return token;
  },
  set(value) {
    token = value;
  },
  clear() {
    token = "";
  },
};

// One exchange in flight per tab, shared by everyone who sees a 401 —
// otherwise three concurrent calls would spend the cookie three times.
let refreshing = null;

// Trades the refresh cookie for a fresh id_token. Answers false when
// there is no session to save; then, and only then, does the user log in
// again.
//
// shortcut: INERT against the issuer this is deployed with. Measured
// 2026-10-31: its refresh grant answers 200 with access_token,
// expires_in, scope and token_type and NO id_token -- which is the
// credential postbud authenticates with -- so every refresh here fails
// at the check below and the user still meets the login gate. The same
// answer carries no replacement refresh token either, and the token is
// reusable, so the rotation handling (the 400 retry, the rotated cookie
// server-side) is untested against reality: rotation happens on the
// authorization_code grant, not this one. Upgrade when the issuer
// reissues an id_token from the refresh grant, after which nothing here
// needs changing; the alternative is authenticating API calls with the
// access token, which means validating those server-side.
export function refreshSession() {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    try {
      for (let attempt = 0; attempt < 2; attempt++) {
        const res = await fetch("/admin/api/oidc/refresh", { method: "POST" });
        if (res.ok) {
          // postbud authenticates API calls with the id_token, not the
          // access token, so a refresh that reissues no id_token buys
          // nothing and is a failed refresh.
          const body = await res.json().catch(() => ({}));
          if (!body.id_token) return false;
          auth.set(body.id_token);
          return true;
        }
        // 401 = no cookie, so there is no session to rescue. 400 = the
        // issuer refused it, which may be the ROTATION: two tabs can
        // spend the same cookie at once, and the loser is refused a
        // token that was just rotated away. The winner's Set-Cookie
        // lands in the shared cookie jar, so one more attempt carries
        // the new token by itself.
        if (res.status !== 400) return false;
        await new Promise((r) => setTimeout(r, 400));
      }
      return false;
    } catch {
      return false;
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

// Drops the refresh cookie server-side. Without this the cookie would
// survive the logout and the next visit would sign the user straight
// back in — on a shared machine, as whoever was there before.
export async function endSession() {
  try {
    await fetch("/admin/api/oidc/logout", { method: "POST" });
  } catch {
    // The network can fail; ending the issuer's session anyway is still
    // better than leaving a session that looks alive.
  }
}

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

export async function api(path, opts = {}, mayRefresh = true) {
  const headers = { Authorization: `Bearer ${token}`, ...(opts.headers || {}) };
  if (opts.body) headers["Content-Type"] = "application/json";

  const res = await fetch(`/admin/api${path}`, { ...opts, headers });

  if (res.status === 401) {
    // An hour-old id_token looks exactly like a bad one here, so try the
    // cookie once before giving up. Only a failed refresh drops the
    // token and falls back to the login gate — otherwise every section
    // would fail one by one on the hour.
    if (mayRefresh && (await refreshSession())) return api(path, opts, false);
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

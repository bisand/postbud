// OIDC authorization-code + PKCE, browser side.
//
// The token exchange goes through postbud (/admin/api/oidc/token), never
// straight to the issuer: no CORS needed there, and an optional client
// secret stays server-side.
//
// SHA-256 is hand-rolled because `crypto.subtle` only exists in secure
// contexts, and the admin is legitimately served over plain HTTP on a
// private network (VPN/tailnet). The PKCE challenge needs a correct
// hash, not a secret-bearing one. `crypto.getRandomValues` is NOT
// context-gated and is used for the verifier and state.

function sha256(bytes) {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
  ]);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));

  const len = bytes.length;
  const bitLen = len * 8;
  const padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
  padded.set(bytes);
  padded[len] = 0x80;
  new DataView(padded.buffer).setUint32(padded.length - 4, bitLen >>> 0);
  new DataView(padded.buffer).setUint32(padded.length - 8, Math.floor(bitLen / 2 ** 32));

  const w = new Uint32Array(64);
  const view = new DataView(padded.buffer);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  new Uint32Array(out.buffer); // ensure alignment
  const dv = new DataView(out.buffer);
  H.forEach((word, i) => dv.setUint32(i * 4, word));
  return out;
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function randomString(length) {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  return [...values].map((v) => alphabet[v % alphabet.length]).join("");
}

const redirectUri = () => location.origin + "/admin";

export async function fetchConfig() {
  const res = await fetch("/admin/api/config");
  if (!res.ok) return { version: "", oidc: { enabled: false } };
  return res.json();
}

export function beginLogin(cfg) {
  const verifier = randomString(64);
  const state = randomString(32);
  sessionStorage.setItem(
    "postbud-oidc-flight",
    JSON.stringify({ verifier, state }),
  );
  const challenge = base64url(sha256(new TextEncoder().encode(verifier)));

  const url = new URL(cfg.authorization_endpoint);
  url.searchParams.set("client_id", cfg.client_id);
  url.searchParams.set("redirect_uri", redirectUri());
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid profile email");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  location.assign(url);
}

/// End the session at the ISSUER, not just here.
///
/// Forgetting our own token only makes this browser stop presenting it;
/// the issuer's own session survives, so signing in again hands the next
/// person straight back in without a password. That is the whole point
/// of a sign-out button on a shared machine.
///
/// The id_token is sent as `id_token_hint` so the issuer can end the
/// session without a confirmation round-trip. No
/// `post_logout_redirect_uri`: it must be pre-registered on the client,
/// and an unregistered one is a hard error at a spec-compliant issuer —
/// landing on the issuer's own "signed out" page is a smaller price than
/// a sign-out that 400s.
///
/// Returns false when the issuer advertises no end-session endpoint, so
/// the caller can still clear local state and say what happened.
export function endIssuerSession(cfg, idToken) {
  if (!cfg?.end_session_endpoint) return false;
  const url = new URL(cfg.end_session_endpoint);
  if (idToken) url.searchParams.set("id_token_hint", idToken);
  location.assign(url);
  return true;
}

/// Handle a ?code= callback if one is present. Returns the id_token, or
/// null when this page load is not an OIDC callback.
export async function completeLogin() {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  if (!code) return null;

  // The query is consumed exactly once; reloading the page must not
  // retry a spent code.
  history.replaceState(null, "", location.pathname + location.hash);

  const flight = JSON.parse(
    sessionStorage.getItem("postbud-oidc-flight") || "null",
  );
  sessionStorage.removeItem("postbud-oidc-flight");
  if (!flight || params.get("state") !== flight.state) {
    throw new Error("Login state mismatch — please try again.");
  }

  const res = await fetch("/admin/api/oidc/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      code_verifier: flight.verifier,
      redirect_uri: redirectUri(),
    }),
  });
  const body = await res.json();
  if (!res.ok || !body.id_token) {
    throw new Error(body.error_description || body.error || "Token exchange failed.");
  }
  return body.id_token;
}

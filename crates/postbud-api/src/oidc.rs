//! OIDC login for the admin surface.
//!
//! postbud is a relying party and nothing more: the ISSUER owns accounts,
//! passwords, sessions and MFA; postbud validates the id_token it is
//! handed and then decides authorization itself against a configured
//! allowlist. Being logged in proves who you are, not that you may
//! administer mail. Any spec-compliant issuer works — the issuer URL is
//! configuration, never code.
//!
//! Flow: the SPA runs authorization-code + PKCE against the issuer, then
//! posts the code to `/admin/api/oidc/token`, which proxies the exchange
//! server-side (no CORS against the issuer, and an optional client
//! secret never reaches the browser). The SPA authenticates API calls
//! with the id_token: its `aud` is our client id, its signature and
//! expiry are checked against the issuer's JWKS, and its `sub`/`email`
//! must be on the allowlist.
//!
//! The proxy also KEEPS the refresh token the issuer hands out: it goes
//! back as an HttpOnly cookie, and `POST /admin/api/oidc/refresh` spends
//! it, so a long-lived credential never exists anywhere JavaScript can
//! reach it and an expired id_token does not mean a new login.
//!
//! `ADMIN_TOKEN` remains valid alongside — the break-glass path. An IdP
//! outage must not lock the operator out of their own mail admin.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use axum::extract::State;
use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

pub struct OidcAdmin {
    pub issuer: String,
    pub client_id: String,
    client_secret: Option<String>,
    /// Who may administer. Each entry is an email (matched
    /// case-insensitively against `email`) or a subject id (matched
    /// exactly against `sub`). Empty is refused at startup — an OIDC
    /// login where everyone at the issuer is an admin is a
    /// misconfiguration, not a default.
    users: Vec<String>,
    /// Static JWKS for dev and tests — signatures are still validated,
    /// there is just no network fetch. Same pattern as OIDC_JWKS_FILE in
    /// the systems this grew out of.
    jwks_static: Option<JwkSet>,
    jwks_cache: RwLock<Option<JwkSet>>,
    discovery: RwLock<Option<Discovery>>,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// RP-initiated logout. Optional: an issuer without one simply gets
    /// no end-session step, and signing out stays local.
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

/// The identity a verified id_token asserts.
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
}

impl OidcAdmin {
    /// Read configuration from the environment. `None` when the feature
    /// is off (no issuer configured); an error when it is half-configured,
    /// because a login that silently authorizes nobody — or everybody —
    /// must fail at startup, not at first use.
    pub fn from_env() -> anyhow::Result<Option<Arc<Self>>> {
        let Ok(issuer) = std::env::var("ADMIN_OIDC_ISSUER") else {
            return Ok(None);
        };
        let issuer = issuer.trim_end_matches('/').to_string();
        let client_id = std::env::var("ADMIN_OIDC_CLIENT_ID")
            .context("ADMIN_OIDC_ISSUER is set but ADMIN_OIDC_CLIENT_ID is not")?;
        // Bootstrap-only: once the admin-user table has rows, this list
        // is inert and can be dropped from the environment entirely.
        let users: Vec<String> = std::env::var("ADMIN_OIDC_USERS")
            .unwrap_or_default()
            .split(',')
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();

        let jwks_static = match std::env::var("ADMIN_OIDC_JWKS_FILE") {
            Ok(path) => {
                let raw = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading ADMIN_OIDC_JWKS_FILE {path}"))?;
                Some(serde_json::from_str(&raw).context("parsing ADMIN_OIDC_JWKS_FILE")?)
            }
            Err(_) => None,
        };

        Ok(Some(Arc::new(Self {
            issuer,
            client_id,
            client_secret: std::env::var("ADMIN_OIDC_CLIENT_SECRET").ok(),
            users,
            jwks_static,
            jwks_cache: RwLock::new(None),
            discovery: RwLock::new(None),
            http: reqwest::Client::new(),
        })))
    }

    /// Build with a static JWKS: no discovery, no network. What
    /// `ADMIN_OIDC_JWKS_FILE` uses, and what the tests use — signatures
    /// are validated for real either way.
    pub fn with_static_jwks(
        issuer: &str,
        client_id: &str,
        users: &[&str],
        jwks_json: &str,
    ) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            client_secret: None,
            users: users.iter().map(|u| u.to_string()).collect(),
            jwks_static: Some(serde_json::from_str(jwks_json).context("parsing static JWKS")?),
            jwks_cache: RwLock::new(None),
            discovery: RwLock::new(None),
            http: reqwest::Client::new(),
        }))
    }

    async fn discovery(&self) -> anyhow::Result<Discovery> {
        if let Some(d) = self.discovery.read().await.clone() {
            return Ok(d);
        }
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        let d: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetching {url}"))?
            .error_for_status()
            .context("discovery document")?
            .json()
            .await
            .context("parsing discovery document")?;
        *self.discovery.write().await = Some(d.clone());
        Ok(d)
    }

    async fn jwks(&self, refresh: bool) -> anyhow::Result<JwkSet> {
        if let Some(set) = &self.jwks_static {
            return Ok(set.clone());
        }
        if !refresh && let Some(set) = self.jwks_cache.read().await.clone() {
            return Ok(set);
        }
        let uri = self.discovery().await?.jwks_uri;
        let set: JwkSet = self
            .http
            .get(&uri)
            .send()
            .await
            .with_context(|| format!("fetching JWKS {uri}"))?
            .error_for_status()
            .context("JWKS endpoint")?
            .json()
            .await
            .context("parsing JWKS")?;
        *self.jwks_cache.write().await = Some(set.clone());
        Ok(set)
    }

    /// Validate an id_token: signature against the issuer's JWKS, iss,
    /// aud = our client id, exp. Authentication ONLY — who this identity
    /// may act as is decided by the admin-user table (or, while it is
    /// empty, the env allowlist), never here. Any failure is one error
    /// kind — a caller probing the gate learns nothing about which check
    /// refused them.
    pub async fn verify(&self, token: &str) -> Result<Identity, ()> {
        let header = decode_header(token).map_err(|_| ())?;
        let kid = header.kid.ok_or(())?;

        // Unknown kid once means a rotated key: refetch and retry once.
        let mut jwks = self.jwks(false).await.map_err(|_| ())?;
        if jwks.find(&kid).is_none() && self.jwks_static.is_none() {
            jwks = self.jwks(true).await.map_err(|_| ())?;
        }
        let jwk = jwks.find(&kid).ok_or(())?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| ())?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.client_id]);

        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| ())?
            .claims;

        Ok(Identity {
            sub: claims.sub,
            email: claims.email,
        })
    }

    /// Is this identity on the ENVIRONMENT allowlist? Only consulted
    /// while the admin-user table is empty — the bootstrap window.
    pub fn env_allowlisted(&self, identity: &Identity) -> bool {
        self.users.iter().any(|u| {
            u == &identity.sub
                || identity
                    .email
                    .as_deref()
                    .is_some_and(|e| e.eq_ignore_ascii_case(u))
        })
    }
}

/// An authenticated (not yet authorized) identity from a verified token.
#[derive(Debug, Clone)]
pub struct Identity {
    pub sub: String,
    pub email: Option<String>,
}

impl Identity {
    /// The name audit fields carry: the email when there is one, the
    /// subject id otherwise.
    pub fn actor(&self) -> &str {
        self.email.as_deref().unwrap_or(&self.sub)
    }
}

// ------------------------------------------------------------- endpoints

/// `GET /admin/api/config` — unauthenticated: the login page needs it
/// before anyone is logged in. Carries no secrets — the version and the
/// OIDC parameters any relying-party redirect would reveal anyway.
pub async fn config(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let oidc = match &state.admin_oidc {
        None => serde_json::json!({ "enabled": false }),
        Some(oidc) => {
            let discovery = oidc.discovery().await.map_err(ApiError::Internal)?;
            serde_json::json!({
                "enabled": true,
                "issuer": oidc.issuer,
                "client_id": oidc.client_id,
                "authorization_endpoint": discovery.authorization_endpoint,
                // Without this the UI can only forget its own token, and
                // the issuer's session outlives the sign-out entirely.
                "end_session_endpoint": discovery.end_session_endpoint,
            })
        }
    };
    Ok(Json(serde_json::json!({
        "version": crate::version(),
        "oidc": oidc,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

/// `POST /admin/api/oidc/token` — proxies the code exchange to the
/// issuer. Server-side so the issuer needs no CORS for us and an
/// optional client secret stays out of the browser. The issuer's error
/// body is passed through on failure: "invalid_grant" in the console
/// beats "400" with no explanation.
///
/// On SUCCESS the answer is not passed through verbatim: the refresh
/// token is removed and returned as an HttpOnly cookie instead (see
/// [`REFRESH_COOKIE`]).
pub async fn exchange(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ExchangeRequest>,
) -> ApiResult<Response> {
    let Some(oidc) = &state.admin_oidc else {
        return Err(ApiError::AdminDisabled);
    };
    let token_endpoint = oidc
        .discovery()
        .await
        .map_err(ApiError::Internal)?
        .token_endpoint;

    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", req.code),
        ("redirect_uri", req.redirect_uri),
        ("client_id", oidc.client_id.clone()),
        ("code_verifier", req.code_verifier),
    ];
    if let Some(secret) = &oidc.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let upstream = oidc
        .http
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| ApiError::Internal(anyhow!("token endpoint: {e}")))?;

    let ok = upstream.status().is_success();
    let body = upstream
        .text()
        .await
        .map_err(|e| ApiError::Internal(anyhow!("reading token response: {e}")))?;
    if !ok {
        return Ok((
            StatusCode::BAD_REQUEST,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response());
    }

    // The refresh token is split off into an HttpOnly cookie rather than
    // handed to the page; everything else goes through as it came.
    let (body, cookie) = split_refresh_token(&headers, &body)?;
    let mut response = (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().insert(
            axum::http::header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| ApiError::Internal(anyhow!("unusable refresh token from issuer")))?,
        );
    }
    Ok(response)
}

// ------------------------------------------------- the refresh cookie

/// The issuer hands out a long-lived refresh token on every code
/// exchange. It never reaches JavaScript: it is split off here and sent
/// back as an HttpOnly cookie, so an XSS can spend the hour already
/// running and cannot mint itself another session. This proxy is already
/// the only code that talks to the token endpoint, so it is also the
/// natural keeper.
const REFRESH_COOKIE: &str = "postbud_admin_refresh";

/// How long the cookie — and therefore the session — may live. The
/// issuer's own refresh token lives far longer; a mail admin console
/// does not need that. Twelve hours covers a working day without
/// carrying the session overnight.
const REFRESH_COOKIE_MAX_AGE: i64 = 12 * 3600;

/// `Secure` only when the request actually arrived over TLS.
///
/// This is WEAKER than deriving it from the hostname: the day a proxy
/// stops setting `X-Forwarded-Proto` the attribute silently disappears.
/// postbud cannot do better. The admin surface is legitimately served
/// over plain HTTP on a private network — the hand-rolled SHA-256 in
/// ui/admin/src/lib/oidc.js exists because `crypto.subtle` needs a
/// secure context — and a `Secure` cookie is never stored over plain
/// HTTP on a non-loopback host, so setting it unconditionally would mean
/// nobody could log in at all. Here the tailnet, not TLS, is the
/// confidentiality boundary: a deployment property, not an oversight.
fn arrived_over_tls(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|proto| {
            proto
                .split(',')
                .next()
                .is_some_and(|first| first.trim().eq_ignore_ascii_case("https"))
        })
}

/// `Path=/admin/api/oidc` so only the two routes that spend the cookie
/// ever see it; `SameSite=Strict` because both are POSTed by our own
/// page.
fn refresh_cookie(headers: &axum::http::HeaderMap, value: &str, max_age: i64) -> String {
    let secure = if arrived_over_tls(headers) {
        " Secure;"
    } else {
        ""
    };
    format!(
        "{REFRESH_COOKIE}={value}; Path=/admin/api/oidc; Max-Age={max_age}; \
         HttpOnly;{secure} SameSite=Strict"
    )
}

fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| {
            c.trim()
                .strip_prefix(name)?
                .strip_prefix('=')
                .map(str::to_string)
        })
}

/// Strip `refresh_token` out of the issuer's answer and turn it into a
/// `Set-Cookie`. The page gets everything else verbatim.
fn split_refresh_token(
    headers: &axum::http::HeaderMap,
    body: &str,
) -> Result<(String, Option<String>), ApiError> {
    let mut parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| ApiError::Internal(anyhow!("token endpoint returned non-JSON: {e}")))?;
    let refresh = parsed
        .as_object_mut()
        .and_then(|o| o.remove("refresh_token"))
        .and_then(|v| v.as_str().map(str::to_string));
    let cookie = refresh.map(|r| refresh_cookie(headers, &r, REFRESH_COOKIE_MAX_AGE));
    Ok((parsed.to_string(), cookie))
}

/// `POST /admin/api/oidc/refresh` — spends the refresh cookie so an
/// expired id_token does not mean a new login. Nothing is read from the
/// request body: the credential is the cookie, which the page cannot
/// read, forge or send anywhere else.
///
/// 401 means there is no cookie (nobody is logged in here, so do not
/// retry); 400 means the issuer refused one, which may be the rotation
/// race between two tabs and is worth one retry. The browser depends on
/// that distinction.
///
/// Unlike [`exchange`], the issuer's error body is NOT passed through: a
/// reused-token error names the token.
pub async fn refresh(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> ApiResult<Response> {
    let Some(oidc) = &state.admin_oidc else {
        return Err(ApiError::AdminDisabled);
    };
    let refresh_token = cookie_value(&headers, REFRESH_COOKIE).ok_or(ApiError::Unauthorized)?;
    let token_endpoint = oidc
        .discovery()
        .await
        .map_err(ApiError::Internal)?
        .token_endpoint;

    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token),
        ("client_id", oidc.client_id.clone()),
    ];
    if let Some(secret) = &oidc.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let upstream = oidc
        .http
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| ApiError::Internal(anyhow!("token endpoint: {e}")))?;
    let status = upstream.status();
    let body = upstream
        .text()
        .await
        .map_err(|e| ApiError::Internal(anyhow!("reading token response: {e}")))?;
    if !status.is_success() {
        eprintln!("postbud: admin token refresh refused ({status}): {body}");
        return Err(ApiError::BadRequest(
            "the issuer refused the session".into(),
        ));
    }

    // The issuer ROTATES: the token just spent is dead and the answer
    // carries its replacement. Dropping it would log the user out when
    // the new access token expires, with nothing in any log to say why.
    let (body, cookie) = split_refresh_token(&headers, &body)?;
    let mut response = (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().insert(
            axum::http::header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| ApiError::Internal(anyhow!("unusable refresh token from issuer")))?,
        );
    }
    Ok(response)
}

/// `POST /admin/api/oidc/logout` — drops the refresh cookie. Not
/// decoration: without it the refresh token outlives the logout and the
/// next visit signs the user straight back in — on a shared machine, as
/// whoever was there before.
pub async fn logout(headers: axum::http::HeaderMap) -> Response {
    (
        StatusCode::NO_CONTENT,
        [(
            axum::http::header::SET_COOKIE,
            refresh_cookie(&headers, "", 0),
        )],
    )
        .into_response()
}

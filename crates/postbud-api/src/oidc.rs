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
//! `ADMIN_TOKEN` remains valid alongside — the break-glass path. An IdP
//! outage must not lock the operator out of their own mail admin.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use axum::extract::State;
use axum::{Json, http::StatusCode, response::IntoResponse};
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
        let users: Vec<String> = std::env::var("ADMIN_OIDC_USERS")
            .context("ADMIN_OIDC_ISSUER is set but ADMIN_OIDC_USERS is not")?
            .split(',')
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();
        if users.is_empty() {
            return Err(anyhow!("ADMIN_OIDC_USERS must name at least one admin"));
        }

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

    /// Validate an id_token and check the allowlist. Any failure is one
    /// error kind — a caller probing the gate learns nothing about which
    /// check refused them.
    pub async fn verify(&self, token: &str) -> Result<(), ()> {
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

        let allowed = self.users.iter().any(|u| {
            u == &claims.sub
                || claims
                    .email
                    .as_deref()
                    .is_some_and(|e| e.eq_ignore_ascii_case(u))
        });
        if allowed { Ok(()) } else { Err(()) }
    }
}

// ------------------------------------------------------------- endpoints

/// `GET /admin/api/oidc/config` — unauthenticated: the login page needs
/// it before anyone is logged in. Carries no secrets.
pub async fn config(State(state): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let Some(oidc) = &state.admin_oidc else {
        return Ok(Json(serde_json::json!({ "enabled": false })));
    };
    let discovery = oidc.discovery().await.map_err(ApiError::Internal)?;
    Ok(Json(serde_json::json!({
        "enabled": true,
        "issuer": oidc.issuer,
        "client_id": oidc.client_id,
        "authorization_endpoint": discovery.authorization_endpoint,
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
pub async fn exchange(
    State(state): State<AppState>,
    Json(req): Json<ExchangeRequest>,
) -> ApiResult<impl IntoResponse> {
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

    let status = if upstream.status().is_success() {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    let body = upstream
        .text()
        .await
        .map_err(|e| ApiError::Internal(anyhow!("reading token response: {e}")))?;

    Ok((
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    ))
}

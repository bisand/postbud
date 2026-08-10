//! The HTTP API.
//!
//! Deliberately small and boring, in the shape callers already know from
//! hosted providers: submit a message, get an id, ask about the id later.
//!
//! This is the ONLY way to send: the relay accepts submission solely from
//! postbud's own delivery worker, so nothing can route around the
//! suppression list, the dedup and the delivery record.

pub mod admin;
pub mod auth;
pub mod bounces;
pub mod error;
pub mod messages;
pub mod oidc;
pub mod suppressions;

use axum::routing::{delete, get, post};
use axum::{Json, Router};
use sqlx::PgPool;
use tower_http::catch_panic::CatchPanicLayer;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// Shared secret the relay presents when piping in a bounce. Separate
    /// from the tenant keys because ingesting a bounce can add addresses to
    /// the GLOBAL suppression list — a different, and more dangerous,
    /// privilege than sending mail.
    pub bounce_token: Option<String>,
    /// Token for the admin surface (`/admin`). Separate again: an admin
    /// mints and revokes tenant keys, a strictly greater privilege than
    /// holding one. With OIDC configured this is the break-glass path;
    /// with neither set the surface is off and says so.
    pub admin_token: Option<String>,
    /// OIDC login for the admin surface (issuer-configurable relying
    /// party + allowlist). See [`oidc::OidcAdmin`].
    pub admin_oidc: Option<std::sync::Arc<oidc::OidcAdmin>>,
    /// Default SPF value for newly registered sending domains
    /// (`DNS_SPF_DEFAULT`, e.g. `v=spf1 ip4:203.0.113.5 -all`). Unset =
    /// every domain registration must state its SPF explicitly.
    pub spf_default: Option<String>,
}

/// The version this binary identifies as. Baked in at image build from
/// the git tag (`POSTBUD_VERSION`); a local cargo build says so instead
/// of impersonating a release.
pub fn version() -> &'static str {
    option_env!("POSTBUD_VERSION").unwrap_or(concat!("v", env!("CARGO_PKG_VERSION"), "-dev"))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/messages", post(messages::submit))
        .route("/v1/messages/{id}", get(messages::status))
        .route("/v1/suppressions", get(suppressions::list))
        .route("/v1/suppressions", post(suppressions::add))
        .route("/v1/suppressions/{id}", delete(suppressions::remove))
        .route("/v1/bounces", post(bounces::ingest))
        .merge(admin::router())
        // A panic in one request becomes a 500, never a dead process that
        // stops delivering everyone else's mail.
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

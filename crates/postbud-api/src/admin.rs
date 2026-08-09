//! The admin surface: `/admin` (embedded UI) and `/admin/api/*`.
//!
//! Authentication is a single `ADMIN_TOKEN`, deliberately separate from the
//! tenant keys: a tenant key sends mail, the admin token mints and revokes
//! tenant keys — a strictly greater privilege that must not be reachable
//! from a leaked tenant credential. When the variable is unset the whole
//! surface answers 503 and says so, rather than pretending to be a login
//! problem.
//!
//! Exposure note: the API listens on a NodePort the host firewall only
//! accepts from loopback and the tailnet, so this surface is never on the
//! public internet. The token is defence in depth, not the only wall.

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router, routing::get, routing::post};
use chrono::{DateTime, Utc};
use include_dir::{Dir, include_dir};
use postbud_core::address;
use postbud_db::{admin, suppression, tenant};
use serde::Deserialize;
use uuid::Uuid;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

/// The compiled Svelte app. Checked-in dist, embedded at compile time —
/// cargo never needs node.
static UI: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../ui/admin/dist");

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin", get(ui_index))
        .route("/admin/assets/{*path}", get(ui_asset))
        .route("/admin/api/overview", get(overview))
        .route("/admin/api/messages", get(messages))
        .route("/admin/api/messages/{id}", get(message_detail))
        .route(
            "/admin/api/suppressions",
            get(suppressions).post(suppress_add),
        )
        .route(
            "/admin/api/suppressions/{id}",
            axum::routing::delete(suppress_remove),
        )
        .route("/admin/api/tenants", get(tenants).post(tenant_create))
        .route("/admin/api/tenants/{id}/rotate-key", post(tenant_rotate))
        .route("/admin/api/tenants/{id}/active", post(tenant_active))
        .route(
            "/admin/api/tenants/{id}/domains",
            axum::routing::put(tenant_domains),
        )
        .route("/admin/api/bounces", get(bounces))
        .route("/admin/api/bounces/{id}/raw", get(bounce_raw))
        .route("/admin/api/oidc/config", get(crate::oidc::config))
        .route("/admin/api/oidc/token", post(crate::oidc::exchange))
}

// ------------------------------------------------------------------- auth

/// An authenticated admin. Same seam trick as [`crate::auth::Tenant`]:
/// adding this as a handler argument is what protects the route, so no
/// admin endpoint can be added that forgets to check.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if state.admin_token.is_none() && state.admin_oidc.is_none() {
            return Err(ApiError::AdminDisabled);
        }

        let presented = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or(ApiError::Unauthorized)?;

        // Path 1: the static token. Compare digests, not strings: the
        // comparison runs over two fixed 32-byte values, so its timing
        // says nothing about where the first differing byte was.
        if let Some(configured) = state.admin_token.as_deref()
            && postbud_core::apikey::hash(presented) == postbud_core::apikey::hash(configured)
        {
            return Ok(Admin);
        }

        // Path 2: an OIDC id_token — signature against the issuer's
        // JWKS, iss/aud/exp, then the allowlist.
        if let Some(oidc) = &state.admin_oidc
            && oidc.verify(presented).await.is_ok()
        {
            return Ok(Admin);
        }

        Err(ApiError::Unauthorized)
    }
}

// ---------------------------------------------------------------- queries

async fn overview(
    State(state): State<AppState>,
    _admin: Admin,
) -> ApiResult<Json<admin::Overview>> {
    Ok(Json(admin::overview(&state.pool).await?))
}

/// One page of a keyset-paged list. `next` carries the cursor for the
/// following (older) page, or is null on the last page. Requesting
/// `limit` rows actually fetches `limit + 1` — the presence of the extra
/// row is what proves there IS a next page, without a COUNT(*) that
/// would rescan the table and defeat the point of paging.
#[derive(Debug, serde::Serialize)]
struct Page<T, C> {
    items: Vec<T>,
    next: Option<C>,
}

fn paginate<T, C>(mut items: Vec<T>, limit: usize, cursor: impl Fn(&T) -> C) -> Page<T, C> {
    let next = if items.len() > limit {
        items.truncate(limit);
        items.last().map(&cursor)
    } else {
        None
    };
    Page { items, next }
}

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    tenant: Option<String>,
    status: Option<String>,
    rcpt: Option<String>,
    before: Option<DateTime<Utc>>,
    before_id: Option<Uuid>,
    limit: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
struct MessageCursor {
    before: DateTime<Utc>,
    before_id: Uuid,
}

async fn messages(
    State(state): State<AppState>,
    _admin: Admin,
    Query(q): Query<MessagesQuery>,
) -> ApiResult<Json<Page<admin::MessageRow, MessageCursor>>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let filter = admin::MessageFilter {
        tenant: q.tenant.as_deref().filter(|t| !t.is_empty()),
        status: q.status.as_deref().filter(|s| !s.is_empty()),
        rcpt: q.rcpt.as_deref().filter(|r| !r.is_empty()),
        before: q.before.zip(q.before_id),
        limit: limit + 1,
    };
    let rows = admin::messages(&state.pool, &filter).await?;
    Ok(Json(paginate(rows, limit as usize, |m| MessageCursor {
        before: m.created_at,
        before_id: m.id,
    })))
}

async fn message_detail(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<admin::MessageDetail>> {
    admin::message_detail(&state.pool, id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

#[derive(Debug, Deserialize)]
struct SuppressionsQuery {
    address: Option<String>,
    #[serde(default)]
    include_removed: bool,
    before_id: Option<i64>,
    limit: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
struct IdCursor {
    before_id: i64,
}

async fn suppressions(
    State(state): State<AppState>,
    _admin: Admin,
    Query(q): Query<SuppressionsQuery>,
) -> ApiResult<Json<Page<admin::SuppressionRow, IdCursor>>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let address = q.address.as_deref().filter(|a| !a.is_empty());
    let rows = admin::suppressions(
        &state.pool,
        address,
        q.include_removed,
        q.before_id,
        limit + 1,
    )
    .await?;
    Ok(Json(paginate(rows, limit as usize, |s| IdCursor {
        before_id: s.id,
    })))
}

#[derive(Debug, Deserialize)]
struct SuppressAdd {
    address: String,
    /// Scope to one tenant, or leave unset for a global block. The admin
    /// may create global entries — unlike a tenant, which only ever blocks
    /// for itself.
    tenant_id: Option<Uuid>,
    detail: Option<String>,
}

async fn suppress_add(
    State(state): State<AppState>,
    _admin: Admin,
    Json(req): Json<SuppressAdd>,
) -> ApiResult<StatusCode> {
    let address = address::normalize(&req.address)
        .map_err(|err| ApiError::BadRequest(format!("address: {err}")))?;

    suppression::add(
        &state.pool,
        req.tenant_id,
        &address,
        "manual",
        "admin",
        req.detail.as_deref(),
    )
    .await?;

    Ok(StatusCode::CREATED)
}

async fn suppress_remove(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    if suppression::remove(&state.pool, id, "admin").await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ---------------------------------------------------------------- tenants

async fn tenants(
    State(state): State<AppState>,
    _admin: Admin,
) -> ApiResult<Json<Vec<tenant::AdminTenant>>> {
    Ok(Json(tenant::admin_list(&state.pool).await?))
}

#[derive(Debug, Deserialize)]
struct TenantCreate {
    name: String,
    from_domains: Vec<String>,
    note: Option<String>,
}

fn clean_domains(raw: &[String]) -> Result<Vec<String>, ApiError> {
    let domains: Vec<String> = raw
        .iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    if domains.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one sending domain is required".into(),
        ));
    }
    for domain in &domains {
        if !domain.contains('.') || domain.contains(['@', ' ', '/']) {
            return Err(ApiError::BadRequest(format!(
                "'{domain}' does not look like a domain"
            )));
        }
    }
    Ok(domains)
}

async fn tenant_create(
    State(state): State<AppState>,
    _admin: Admin,
    Json(req): Json<TenantCreate>,
) -> ApiResult<Json<serde_json::Value>> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let domains = clean_domains(&req.from_domains)?;

    let (created, key) = tenant::create(&state.pool, name, &domains, req.note.as_deref()).await?;

    // The key appears in this response and nowhere else, ever — postbud
    // stores only its digest and cannot repeat it.
    Ok(Json(serde_json::json!({
        "id": created.id,
        "name": created.name,
        "from_domains": created.from_domains,
        "api_key": key,
    })))
}

async fn tenant_rotate(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let key = tenant::rotate_key(&state.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(serde_json::json!({ "api_key": key })))
}

#[derive(Debug, Deserialize)]
struct TenantActive {
    active: bool,
}

async fn tenant_active(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
    Json(req): Json<TenantActive>,
) -> ApiResult<StatusCode> {
    if tenant::set_active(&state.pool, id, req.active).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

#[derive(Debug, Deserialize)]
struct TenantDomains {
    from_domains: Vec<String>,
}

async fn tenant_domains(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
    Json(req): Json<TenantDomains>,
) -> ApiResult<StatusCode> {
    let domains = clean_domains(&req.from_domains)?;
    if tenant::set_domains(&state.pool, id, &domains).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ---------------------------------------------------------------- bounces

#[derive(Debug, Deserialize)]
struct BouncesQuery {
    before_id: Option<i64>,
    limit: Option<i64>,
}

async fn bounces(
    State(state): State<AppState>,
    _admin: Admin,
    Query(q): Query<BouncesQuery>,
) -> ApiResult<Json<Page<admin::BounceRow, IdCursor>>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows = admin::bounces(&state.pool, q.before_id, limit + 1).await?;
    Ok(Json(paginate(rows, limit as usize, |b| IdCursor {
        before_id: b.id,
    })))
}

async fn bounce_raw(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    let raw = admin::bounce_raw(&state.pool, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], raw).into_response())
}

// --------------------------------------------------------------------- ui

/// The UI shell. Served without auth — it is a static page that holds no
/// data; every byte of actual information behind it requires the token.
/// `no-store` so a redeploy is picked up on the next load.
async fn ui_index() -> Response {
    match UI.get_file("index.html") {
        Some(file) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            file.contents(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Html("<h1>postbud</h1><p>admin UI not built into this binary</p>"),
        )
            .into_response(),
    }
}

/// Vite hashes asset filenames, so a name is its content — immutable
/// caching is exactly right, and an unknown asset is a plain 404, never
/// the app shell.
async fn ui_asset(Path(path): Path<String>) -> Response {
    let Some(file) = UI.get_file(format!("assets/{path}")) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let content_type = match path.rsplit('.').next() {
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    };

    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        file.contents(),
    )
        .into_response()
}

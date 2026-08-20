//! The admin surface: `/admin` (embedded UI) and `/admin/api/*`.
//!
//! Two ways in, both decided by the extractors below: an OIDC login
//! (identity from the issuer, authorization from the admin-user table)
//! and `ADMIN_TOKEN` as the break-glass path. Both are deliberately
//! separate from the tenant keys: a tenant key sends mail, an admin
//! credential mints and revokes tenant keys — a strictly greater
//! privilege that must not be reachable from a leaked tenant credential.
//! With neither configured the whole surface answers 503 and says so,
//! rather than pretending to be a login problem.
//!
//! Exposure note: the API must not listen on the public internet — ours
//! is a NodePort the host firewall only accepts from loopback and the
//! private network, with TLS in front of it (docs/architecture.md §9).
//! These credentials are defence in depth, not the only wall.

use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::{Json, Router, routing::get, routing::post};
use chrono::{DateTime, Utc};
use include_dir::{Dir, include_dir};
use postbud_core::address;
use postbud_db::{admin, dmarc, suppression, tenant};
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
        .route(
            "/admin/api/tenants/{id}/domain-history",
            get(tenant_domain_history),
        )
        .route("/admin/api/tenants/{id}/active", post(tenant_active))
        .route(
            "/admin/api/tenants/{id}/domains",
            axum::routing::put(tenant_domains),
        )
        .route("/admin/api/bounces", get(bounces))
        .route("/admin/api/bounces/{id}/raw", get(bounce_raw))
        .route("/admin/api/me", get(me))
        .route("/admin/api/relay", get(relay_identity))
        .route("/admin/api/domains", get(domains).post(domain_add))
        .route("/admin/api/domains/{id}", axum::routing::delete(domain_end))
        .route("/admin/api/dmarc", get(dmarc_domains))
        .route("/admin/api/dmarc/{domain}", get(dmarc_domain))
        .route("/admin/api/users", get(users).post(user_add))
        .route("/admin/api/users/{id}/role", post(user_role))
        .route("/admin/api/users/{id}", axum::routing::delete(user_end))
        .route("/admin/api/config", get(crate::oidc::config))
        .route("/admin/api/oidc/token", post(crate::oidc::exchange))
}

// ------------------------------------------------------------------- auth

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything, including minting keys and managing users.
    Admin,
    /// Sees everything, changes nothing.
    Viewer,
}

/// An authenticated operator. Same seam trick as [`crate::auth::Tenant`]:
/// adding this as a handler argument is what protects the route, so no
/// admin endpoint can be added that forgets to check. Read endpoints
/// take `Admin` (any role); MUTATING endpoints take [`AdminWrite`], so a
/// viewer cannot change anything and no handler can forget to ask.
pub struct Admin {
    /// Who this is, for the audit fields: an email, a subject id, or
    /// `admin-token`.
    pub actor: String,
    pub role: Role,
}

impl Admin {
    async fn resolve(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
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

        // Path 1: the static token — always the admin role; it is the
        // bootstrap and break-glass credential. Compare digests, not
        // strings: two fixed 32-byte values, so the timing says nothing
        // about where the first differing byte was.
        if let Some(configured) = state.admin_token.as_deref()
            && postbud_core::apikey::hash(presented) == postbud_core::apikey::hash(configured)
        {
            return Ok(Admin {
                actor: "admin-token".into(),
                role: Role::Admin,
            });
        }

        // Path 2: an OIDC id_token. The issuer authenticates (signature,
        // iss, aud, exp); the admin-user TABLE authorizes. While the
        // table is empty the environment allowlist governs — the
        // bootstrap window — and the first row closes it.
        if let Some(oidc) = &state.admin_oidc
            && let Ok(identity) = oidc.verify(presented).await
        {
            let (role, any_active) = postbud_db::admin_user::resolve(
                &state.pool,
                &identity.sub,
                identity.email.as_deref(),
            )
            .await
            .map_err(ApiError::Internal)?;
            let role = match role.as_deref() {
                Some("admin") => Some(Role::Admin),
                Some("viewer") => Some(Role::Viewer),
                Some(_) => None,
                None if !any_active && oidc.env_allowlisted(&identity) => Some(Role::Admin),
                None => None,
            };
            if let Some(role) = role {
                return Ok(Admin {
                    actor: identity.actor().to_string(),
                    role,
                });
            }
        }

        Err(ApiError::Unauthorized)
    }
}

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Admin::resolve(parts, state).await
    }
}

/// An operator allowed to CHANGE things. 403 for a viewer — distinct
/// from 401, because the session is fine; the role is not.
pub struct AdminWrite(pub Admin);

impl FromRequestParts<AppState> for AdminWrite {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let admin = Admin::resolve(parts, state).await?;
        if admin.role != Role::Admin {
            return Err(ApiError::Forbidden);
        }
        Ok(AdminWrite(admin))
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
    /// The page size actually applied, after defaulting and clamping.
    /// Returned rather than assumed: a UI that only shows "newer" and
    /// "older" leaves the operator guessing how much they are looking
    /// at, and a silently clamped request would make that guess wrong.
    limit: i64,
}

/// Rows per page when the caller does not say.
const DEFAULT_PAGE_SIZE: i64 = 10;
/// The most any caller may ask for. The ceiling is the point: without
/// one, `?limit=100000` turns keyset paging back into the full scan it
/// exists to avoid.
const MAX_PAGE_SIZE: i64 = 100;

fn page_size(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE)
}

fn paginate<T, C>(mut items: Vec<T>, limit: i64, cursor: impl Fn(&T) -> C) -> Page<T, C> {
    let keep = limit as usize;
    let next = if items.len() > keep {
        items.truncate(keep);
        items.last().map(&cursor)
    } else {
        None
    };
    Page { items, next, limit }
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
    let limit = page_size(q.limit);
    let filter = admin::MessageFilter {
        tenant: q.tenant.as_deref().filter(|t| !t.is_empty()),
        status: q.status.as_deref().filter(|s| !s.is_empty()),
        rcpt: q.rcpt.as_deref().filter(|r| !r.is_empty()),
        before: q.before.zip(q.before_id),
        limit: limit + 1,
    };
    let rows = admin::messages(&state.pool, &filter).await?;
    Ok(Json(paginate(rows, limit, |m| MessageCursor {
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
    let limit = page_size(q.limit);
    let address = q.address.as_deref().filter(|a| !a.is_empty());
    let rows = admin::suppressions(
        &state.pool,
        address,
        q.include_removed,
        q.before_id,
        limit + 1,
    )
    .await?;
    Ok(Json(paginate(rows, limit, |s| IdCursor {
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
    AdminWrite(admin): AdminWrite,
    Json(req): Json<SuppressAdd>,
) -> ApiResult<StatusCode> {
    let address = address::normalize(&req.address)
        .map_err(|err| ApiError::BadRequest(format!("address: {err}")))?;

    // `source` is the actor: "blocked by andre@…" is an answer,
    // "blocked by admin" is a shrug.
    suppression::add(
        &state.pool,
        req.tenant_id,
        &address,
        "manual",
        &admin.actor,
        req.detail.as_deref(),
    )
    .await?;

    Ok(StatusCode::CREATED)
}

async fn suppress_remove(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    if suppression::remove(&state.pool, id, &admin.actor).await? {
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
    AdminWrite(admin): AdminWrite,
    Json(req): Json<TenantCreate>,
) -> ApiResult<Json<serde_json::Value>> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    let domains = clean_domains(&req.from_domains)?;

    let (created, key) = tenant::create(
        &state.pool,
        name,
        &domains,
        req.note.as_deref(),
        &admin.actor,
    )
    .await?;

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
    AdminWrite(_admin): AdminWrite,
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
    AdminWrite(_admin): AdminWrite,
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

/// What this tenant has been allowed to send as, and who changed it.
///
/// Read-only for every role, including the one that can make the change:
/// an audit record an operator can edit answers nothing.
async fn tenant_domain_history(
    State(state): State<AppState>,
    _admin: Admin,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<tenant::DomainChange>>> {
    Ok(Json(tenant::domain_history(&state.pool, id).await?))
}

async fn tenant_domains(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Path(id): Path<Uuid>,
    Json(req): Json<TenantDomains>,
) -> ApiResult<StatusCode> {
    let domains = clean_domains(&req.from_domains)?;
    if tenant::set_domains(&state.pool, id, &domains, &admin.actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ---------------------------------------------------------------- domains

/// One sending domain with its latest verification snapshot. The
/// `records` array is what the UI renders as paste-ready DNS rows.
#[derive(Debug, serde::Serialize)]
struct DomainView {
    #[serde(flatten)]
    domain: postbud_db::domain::SendingDomain,
    records: Vec<serde_json::Value>,
    check: Option<postbud_db::domain::CheckRow>,
}

/// The paste-ready DNS rows for one domain.
///
/// SPF, DKIM and MX are prescriptions: postbud knows the exact value it
/// requires and compares DNS to it byte-for-byte. DMARC is not — the
/// check only asks that a policy exists, because postbud has no opinion
/// on what yours should be. Showing a made-up `p=none` next to the other
/// three implied it did, under a heading promising the values are the
/// ones compared, beside a Copy button. On a `p=reject` domain that is a
/// one-click downgrade to monitoring-only, and nothing here would report
/// it: the prefix still matches. So once a check has seen the real
/// record, that is what is shown, and it is marked as observed rather
/// than prescribed.
fn record_rows(
    d: &postbud_db::domain::SendingDomain,
    check: Option<&postbud_db::domain::CheckRow>,
) -> Vec<serde_json::Value> {
    let dmarc_observed = check.and_then(|c| c.dmarc_observed.clone());
    let mut rows = vec![
        serde_json::json!({
            "kind": "spf", "type": "TXT", "name": d.domain,
            "value": d.spf_expected,
            "prescribed": true,
        }),
        serde_json::json!({
            "kind": "dkim", "type": "TXT",
            "name": format!("{}._domainkey.{}", d.dkim_selector, d.domain),
            "value": format!("v=DKIM1; h=sha256; k=rsa; p={}", d.dkim_public_key),
            "prescribed": true,
        }),
        match &dmarc_observed {
            Some(observed) => serde_json::json!({
                "kind": "dmarc", "type": "TXT",
                "name": format!("_dmarc.{}", d.domain),
                "value": observed,
                "prescribed": false,
                "note": "published policy, as last seen -- postbud does not require a particular one",
            }),
            None => serde_json::json!({
                "kind": "dmarc", "type": "TXT",
                "name": format!("_dmarc.{}", d.domain),
                "value": "v=DMARC1; p=none",
                "prescribed": false,
                "note": "a suggested starting policy -- nothing is published yet, or inherited from the parent domain",
            }),
        },
    ];
    if let Some(mx) = &d.mx_expected {
        rows.push(serde_json::json!({
            "kind": "mx", "type": "MX", "name": d.domain,
            "value": format!("10 {mx}"),
            "prescribed": true,
        }));
    }
    rows
}

async fn domains(State(state): State<AppState>, _admin: Admin) -> ApiResult<Json<Vec<DomainView>>> {
    let list = postbud_db::domain::list(&state.pool).await?;
    let mut checks = postbud_db::domain::latest_checks(&state.pool).await?;
    Ok(Json(
        list.into_iter()
            .map(|d| {
                let check = checks.remove(&d.id);
                DomainView {
                    records: record_rows(&d, check.as_ref()),
                    check,
                    domain: d,
                }
            })
            .collect(),
    ))
}

#[derive(Debug, serde::Serialize)]
struct RelayView {
    /// The name the relay is expected to answer to, from
    /// `RELAY_PUBLIC_HOST`. None when the installation has not configured
    /// one — nothing is checked then, and the UI says so rather than
    /// showing a green tick for a question nobody asked.
    expected_host: Option<String>,
    check: Option<postbud_db::relay::RelayCheckRow>,
}

/// The relay's own identity: forward DNS, PTR, and the SMTP greeting.
///
/// Read-only and unconditional — there is one relay by design, so there
/// is nothing here to create or delete, and the worker is what refreshes
/// it.
async fn relay_identity(
    State(state): State<AppState>,
    _admin: Admin,
) -> ApiResult<Json<RelayView>> {
    let expected_host = std::env::var("RELAY_PUBLIC_HOST")
        .ok()
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty());

    Ok(Json(RelayView {
        expected_host,
        check: postbud_db::relay::latest(&state.pool).await?,
    }))
}

#[derive(Debug, Deserialize)]
struct DomainAdd {
    domain: String,
    /// The enforcement level this domain is meant to publish, if the
    /// caller has an opinion. Omitted means only the policy's syntax is
    /// checked — which is still worth doing, because DMARC fails open and
    /// an unreadable p= tag protects nothing while looking valid.
    dmarc_policy_expected: Option<String>,
    /// Defaults to authorizing exactly this installation's relay — the
    /// caller may override for include:-style setups.
    spf_expected: Option<String>,
    dkim_selector: String,
    /// The p= value the relay signs with. Pasting the WRONG key here
    /// would make the checker bless a broken setup, which is why the
    /// worker compares byte-for-byte against what DNS serves — garbage
    /// in still turns red the moment the relay's signature fails... but
    /// the check itself can only be as honest as this value.
    dkim_public_key: String,
    mx_expected: Option<String>,
}

async fn domain_add(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Json(req): Json<DomainAdd>,
) -> ApiResult<Json<DomainView>> {
    let domain = req.domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || !domain.contains('.') || domain.contains(['@', ' ', '/']) {
        return Err(ApiError::BadRequest(format!(
            "'{domain}' does not look like a domain"
        )));
    }
    let selector = req.dkim_selector.trim();
    if selector.is_empty() {
        return Err(ApiError::BadRequest("dkim_selector is required".into()));
    }
    let key: String = req
        .dkim_public_key
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"')
        .collect();
    if key.len() < 64 {
        return Err(ApiError::BadRequest(
            "dkim_public_key looks too short to be a key — paste the p= value".into(),
        ));
    }
    let spf = match req.spf_expected.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => match &state.spf_default {
            Some(default) => default.clone(),
            None => {
                return Err(ApiError::BadRequest(
                    "spf_expected is required (DNS_SPF_DEFAULT is not configured)".into(),
                ));
            }
        },
    };

    // Optional: with no stated level only the policy's SYNTAX is checked.
    // Rejected here rather than stored and puzzled over later, since a
    // registry value that is not a policy cannot be compared to one.
    let policy = match req.dmarc_policy_expected.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => {
            let p = p.to_ascii_lowercase();
            if !matches!(p.as_str(), "none" | "quarantine" | "reject") {
                return Err(ApiError::BadRequest(format!(
                    "dmarc_policy_expected must be none, quarantine or reject (got '{p}')"
                )));
            }
            Some(p)
        }
        _ => None,
    };

    let created = postbud_db::domain::add(
        &state.pool,
        &domain,
        &spf,
        selector,
        &key,
        req.mx_expected
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty()),
        policy.as_deref(),
        &admin.actor,
    )
    .await
    .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    Ok(Json(DomainView {
        // Nothing has been checked yet, so the DMARC row falls back to a
        // suggestion — which is honest for a domain that has none.
        records: record_rows(&created, None),
        check: None,
        domain: created,
    }))
}

async fn domain_end(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    if postbud_db::domain::end(&state.pool, id, &admin.actor).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ------------------------------------------------------------------ users

/// `GET /admin/api/me` — who am I, and what may I do. The UI uses it to
/// hide controls a viewer cannot use; the SERVER enforcement lives in
/// [`AdminWrite`], never here.
async fn me(admin: Admin) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "actor": admin.actor, "role": admin.role }))
}

/// What the receivers concluded, per sending domain.
///
/// Read-only, and only ever read-only. A DMARC report is a claim by
/// whoever sent it, and the address in a `rua=` tag is public — anyone
/// can post a report saying anything about any domain. Nothing on this
/// surface may act on one, which is why there is no companion
/// [`AdminWrite`] endpoint here and no button that does anything.
async fn dmarc_domains(
    State(state): State<AppState>,
    _admin: Admin,
) -> ApiResult<Json<Vec<dmarc::DomainSummary>>> {
    Ok(Json(dmarc::summary(&state.pool).await?))
}

#[derive(Debug, Deserialize)]
struct DmarcWindow {
    days: Option<i64>,
}

#[derive(serde::Serialize)]
struct DmarcDetail {
    sources: Vec<dmarc::SourceRollup>,
    daily: Vec<dmarc::DailyPoint>,
}

async fn dmarc_domain(
    State(state): State<AppState>,
    _admin: Admin,
    Path(domain): Path<String>,
    Query(window): Query<DmarcWindow>,
) -> ApiResult<Json<DmarcDetail>> {
    // Clamped rather than trusted: `days` reaches SQL, and an unbounded
    // window on a table that only grows is a slow query waiting for the
    // day there is enough history to notice.
    let days = window.days.unwrap_or(30).clamp(1, 3650);
    let domain = domain.trim().to_ascii_lowercase();
    let (sources, daily) = tokio::try_join!(
        dmarc::sources(&state.pool, &domain, days),
        dmarc::daily(&state.pool, &domain, days),
    )?;
    Ok(Json(DmarcDetail { sources, daily }))
}

async fn users(
    State(state): State<AppState>,
    _admin: Admin,
    Query(q): Query<UsersQuery>,
) -> ApiResult<Json<Vec<postbud_db::admin_user::AdminUser>>> {
    Ok(Json(
        postbud_db::admin_user::list(&state.pool, q.include_ended).await?,
    ))
}

#[derive(Debug, Deserialize)]
struct UsersQuery {
    #[serde(default)]
    include_ended: bool,
}

fn valid_role(role: &str) -> Result<(), ApiError> {
    match role {
        "admin" | "viewer" => Ok(()),
        other => Err(ApiError::BadRequest(format!(
            "unknown role '{other}' (admin or viewer)"
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct UserAdd {
    /// An email (matched case-insensitively against the id_token's
    /// `email`) or an OIDC subject id.
    identifier: String,
    role: String,
    note: Option<String>,
}

async fn user_add(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Json(req): Json<UserAdd>,
) -> ApiResult<Json<postbud_db::admin_user::AdminUser>> {
    let identifier = req.identifier.trim();
    if identifier.is_empty() {
        return Err(ApiError::BadRequest("identifier is required".into()));
    }
    valid_role(&req.role)?;

    let user = postbud_db::admin_user::add(
        &state.pool,
        identifier,
        &req.role,
        req.note.as_deref(),
        &admin.actor,
    )
    .await
    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(user))
}

#[derive(Debug, Deserialize)]
struct UserRole {
    role: String,
}

async fn user_role(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Path(id): Path<i64>,
    Json(req): Json<UserRole>,
) -> ApiResult<StatusCode> {
    valid_role(&req.role)?;
    match postbud_db::admin_user::set_role(&state.pool, id, &req.role, &admin.actor).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::NotFound),
        // The last-admin rule surfaces as a message the operator can act
        // on, not a 500.
        Err(e) => Err(ApiError::BadRequest(e.to_string())),
    }
}

async fn user_end(
    State(state): State<AppState>,
    AdminWrite(admin): AdminWrite,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    match postbud_db::admin_user::end(&state.pool, id, &admin.actor).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::BadRequest(e.to_string())),
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
    let limit = page_size(q.limit);
    let rows = admin::bounces(&state.pool, q.before_id, limit + 1).await?;
    Ok(Json(paginate(rows, limit, |b| IdCursor {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling is load-bearing: without it `?limit=100000` turns
    /// keyset paging back into the full scan it exists to avoid. The
    /// floor matters too — `?limit=0` would fetch one row and report a
    /// next page forever.
    #[test]
    fn page_size_defaults_and_is_clamped_at_both_ends() {
        assert_eq!(page_size(None), DEFAULT_PAGE_SIZE);
        assert_eq!(page_size(Some(25)), 25);
        assert_eq!(page_size(Some(MAX_PAGE_SIZE)), MAX_PAGE_SIZE);
        assert_eq!(page_size(Some(100_000)), MAX_PAGE_SIZE);
        assert_eq!(page_size(Some(0)), 1);
        assert_eq!(page_size(Some(-5)), 1);
    }

    /// The extra row is how a next page is detected without COUNT(*);
    /// it must never be shown, and the applied limit must come back so
    /// the UI can state the page size rather than imply it.
    #[test]
    fn the_probe_row_is_dropped_and_becomes_the_cursor() {
        let full = paginate(vec![1, 2, 3, 4], 3, |n: &i32| *n);
        assert_eq!(full.items, vec![1, 2, 3]);
        assert_eq!(full.next, Some(3), "the cursor is the LAST kept row");
        assert_eq!(full.limit, 3);

        let last = paginate(vec![1, 2], 3, |n: &i32| *n);
        assert_eq!(last.items, vec![1, 2]);
        assert_eq!(last.next, None, "a short page is the end");
    }
}

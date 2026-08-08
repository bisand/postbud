//! The suppression list, over HTTP.
//!
//! Readable and correctable by the tenant, because the alternative is a
//! support request every time an address is suppressed by mistake.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Json, response::IntoResponse};
use chrono::{DateTime, Utc};
use postbud_core::address;
use postbud_db::suppression;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::Tenant;
use crate::error::{ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Narrow to one address — the common case, checking why a particular
    /// customer stopped receiving mail.
    pub address: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub id: i64,
    pub address: String,
    pub reason: String,
    pub source: String,
    pub detail: Option<String>,
    /// True when this applies to every tenant, which is what a hard bounce
    /// produces: the mailbox is gone regardless of who was writing to it.
    pub global: bool,
    pub created_at: DateTime<Utc>,
}

/// `GET /v1/suppressions?address=`
pub async fn list(
    State(state): State<AppState>,
    Tenant(tenant): Tenant,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Vec<Entry>>> {
    let entries = suppression::list(&state.pool, tenant.id, query.address.as_deref()).await?;
    Ok(Json(
        entries
            .into_iter()
            .map(|e| Entry {
                id: e.id,
                address: e.address,
                reason: e.reason,
                source: e.source,
                detail: e.detail,
                global: e.tenant_id.is_none(),
                created_at: e.created_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AddRequest {
    pub address: String,
    pub detail: Option<String>,
}

/// `POST /v1/suppressions`
///
/// A manual addition is always scoped to the calling tenant. One product
/// deciding never to write to an address must not silently stop the other
/// from doing so — only a bounce, which is evidence about the mailbox
/// itself, creates a global entry.
pub async fn add(
    State(state): State<AppState>,
    Tenant(tenant): Tenant,
    Json(req): Json<AddRequest>,
) -> ApiResult<impl IntoResponse> {
    let address = address::normalize(&req.address)
        .map_err(|err| ApiError::BadRequest(format!("address: {err}")))?;

    suppression::add(
        &state.pool,
        Some(tenant.id),
        &address,
        "manual",
        &tenant.name,
        req.detail.as_deref(),
    )
    .await?;

    Ok(StatusCode::CREATED)
}

/// `DELETE /v1/suppressions/{id}`
///
/// A soft delete: the row keeps its history and gains a `removed_at`. Also
/// note what this cannot do — a tenant may lift a global suppression, and
/// that is intended, because the person who knows the mailbox was fixed is
/// the one being told their customer never got the invoice.
pub async fn remove(
    State(state): State<AppState>,
    Tenant(tenant): Tenant,
    Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
    let removed = suppression::remove(&state.pool, id, &tenant.name).await?;
    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

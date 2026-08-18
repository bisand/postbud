//! The relay's queue, reported in.
//!
//! Same shape and same privilege as bounce ingestion: the relay holds no
//! database credentials and no schema knowledge, it just POSTs what
//! `postqueue -j` printed. Parsing lives here so it has tests, rather
//! than in a shell script on a host nobody reads.
//!
//! Sharing `BOUNCE_INGEST_TOKEN` is deliberate -- both endpoints are "the
//! relay telling us what became of mail", and a second secret to rotate
//! would buy nothing. Note the asymmetry in blast radius though: a bounce
//! can suppress an address globally, while a forged queue report can only
//! mislabel delivery state, never stop mail.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use serde::Serialize;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

/// Seconds of slack between `postqueue` running on the relay and this
/// request landing. A message handed over inside that window may legitimately
/// be missing from the snapshot, and must not be read as delivered.
const GRACE_SECS: i64 = 15;

#[derive(Debug, Serialize)]
pub struct QueueResponse {
    pub queued: usize,
    pub delivered: usize,
    pub unmatched: usize,
}

/// `POST /v1/relay/queue` — body is raw `postqueue -j` output.
///
/// An empty body is the healthy case: nothing in the queue. It is also
/// the most consequential input here, because it is what concludes that
/// everything outstanding was delivered — so it must be a deliberate
/// empty string, never a failed command whose output we lost.
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> ApiResult<Json<QueueResponse>> {
    let Some(expected) = state.bounce_token.as_deref() else {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "BOUNCE_INGEST_TOKEN is not configured; refusing to ingest"
        )));
    };

    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or_default();

    if postbud_core::apikey::hash(presented) != postbud_core::apikey::hash(expected) {
        return Err(ApiError::Unauthorized);
    }

    let entries = postbud_core::relayqueue::parse(&body);
    let result = postbud_db::relayqueue::reconcile(&state.pool, &entries, GRACE_SECS).await?;

    Ok(Json(QueueResponse {
        queued: result.queued,
        delivered: result.delivered,
        unmatched: result.unmatched,
    }))
}

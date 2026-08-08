//! Bounce ingestion over HTTP.
//!
//! Postfix's pipe transport hands a raw DSN to this endpoint. It exists as
//! HTTP rather than as a CLI invocation because the relay and postbud may
//! be separate hosts, and because the relay should hold as little as
//! possible: no database credentials, no schema knowledge, no binary to
//! keep in step with the deployment.
//!
//! Authentication is a single shared token rather than a tenant key.
//! Ingesting a bounce is a different privilege from sending mail — it can
//! add addresses to the global suppression list, which is exactly the
//! capability an attacker would want in order to silence a competitor's
//! invoices.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use postbud_db::bounce;
use serde::Serialize;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub reports: usize,
    pub suppressed: usize,
    /// Reports whose queue id matched no message we hold. Expected for old
    /// or purged mail; a persistently high count means the queue id is not
    /// being captured on the way out, and bounce correlation is silently
    /// broken.
    pub unmatched: usize,
}

/// `POST /v1/bounces` — body is the raw DSN, exactly as Postfix piped it.
///
/// Never returns an error for content we could not parse: an unreadable
/// bounce is stored raw and reported as zero reports. The relay must only
/// see a failure when we genuinely did not persist anything, because it
/// reads a non-2xx as "requeue and try again" — which is the right answer
/// then, and the wrong one for a DSN we simply could not read.
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> ApiResult<Json<IngestResponse>> {
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

    // Compare over the digests so the check does not leak length or a
    // prefix through timing.
    if postbud_core::apikey::hash(presented) != postbud_core::apikey::hash(expected) {
        return Err(ApiError::Unauthorized);
    }

    if body.trim().is_empty() {
        return Err(ApiError::BadRequest("empty bounce body".into()));
    }

    let result = bounce::ingest(&state.pool, &body).await?;

    Ok(Json(IngestResponse {
        reports: result.reports,
        suppressed: result.suppressed,
        unmatched: result.unmatched,
    }))
}

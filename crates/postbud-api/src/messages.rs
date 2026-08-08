//! Submitting mail, and asking what became of it.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Json, response::IntoResponse};
use base64::Engine as _;
use postbud_core::{address, authz};
use postbud_db::message::{self, Attachment, NewMessage};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::auth::Tenant;
use crate::error::{ApiError, ApiResult};

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    /// The caller's own id for the business event behind this mail.
    ///
    /// regnmed passes its `utsendelse` id, which is what makes a retry
    /// safe: the same key can never produce a second invoice in the
    /// customer's inbox. Callers without a natural id may omit it, and
    /// then every submission is a new message — which is the honest
    /// behaviour, not a silent guess.
    pub idempotency_key: Option<String>,
    pub from: String,
    pub from_name: Option<String>,
    pub to: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentRequest>,
}

#[derive(Debug, Deserialize)]
pub struct AttachmentRequest {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub id: Uuid,
    pub status: String,
    pub deduplicated: bool,
}

/// `POST /v1/messages`
///
/// Returns 202: accepted for delivery, which is all any mail API can
/// honestly promise at this point. Whether it was delivered is what
/// [`status`] is for.
///
/// A suppressed recipient also returns 202, with `status: "suppressed"`.
/// That is not a fudge — the request was well-formed and we recorded a
/// decision about it. Failing the call would tell the caller their code is
/// wrong when it is the address that is dead.
pub async fn submit(
    State(state): State<AppState>,
    Tenant(tenant): Tenant,
    Json(req): Json<SubmitRequest>,
) -> ApiResult<impl IntoResponse> {
    let mail_from = address::normalize(&req.from)
        .map_err(|err| ApiError::BadRequest(format!("from: {err}")))?;
    let rcpt_to =
        address::normalize(&req.to).map_err(|err| ApiError::BadRequest(format!("to: {err}")))?;
    let reply_to = req
        .reply_to
        .as_deref()
        .map(address::normalize)
        .transpose()
        .map_err(|err| ApiError::BadRequest(format!("reply_to: {err}")))?;

    // The boundary a shared SMTP credential cannot give you: a leaked
    // regnmed key cannot send as networco.
    if !authz::may_send_as(&mail_from, &tenant.from_domains) {
        return Err(ApiError::BadRequest(format!(
            "tenant '{}' may not send as {mail_from} (allowed domains: {})",
            tenant.name,
            tenant.from_domains.join(", ")
        )));
    }

    if req.text.is_none() && req.html.is_none() {
        return Err(ApiError::BadRequest(
            "one of 'text' or 'html' is required".into(),
        ));
    }
    if req.subject.trim().is_empty() {
        return Err(ApiError::BadRequest("subject is required".into()));
    }

    let mut attachments = Vec::with_capacity(req.attachments.len());
    for attachment in &req.attachments {
        let content = base64::engine::general_purpose::STANDARD
            .decode(attachment.content_base64.as_bytes())
            .map_err(|err| {
                ApiError::BadRequest(format!(
                    "attachment '{}': content_base64 is not valid base64: {err}",
                    attachment.filename
                ))
            })?;
        attachments.push(Attachment {
            filename: attachment.filename.clone(),
            content_type: attachment.content_type.clone(),
            content,
        });
    }

    let accepted = message::accept(
        &state.pool,
        &NewMessage {
            tenant_id: tenant.id,
            idempotency_key: req
                .idempotency_key
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            mail_from,
            from_name: req.from_name,
            rcpt_to,
            reply_to,
            subject: req.subject,
            body_text: req.text,
            body_html: req.html,
            attachments,
        },
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(SubmitResponse {
            id: accepted.id,
            status: accepted.status,
            deduplicated: accepted.deduplicated,
        }),
    ))
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub id: Uuid,
    pub status: String,
    pub attempts: i32,
    pub to: String,
    pub subject: String,
    /// Postfix's queue id. Present once the relay accepted the message,
    /// and the value to grep the mail log for.
    pub relay_queue_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `GET /v1/messages/{id}`
///
/// The question regnmed's `utsendelse` log cannot answer on its own: it
/// records that a message was handed off, never whether it arrived.
pub async fn status(
    State(state): State<AppState>,
    Tenant(tenant): Tenant,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<StatusResponse>> {
    let found = message::status(&state.pool, tenant.id, id)
        .await?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(StatusResponse {
        id: found.id,
        status: found.status,
        attempts: found.attempts,
        to: found.rcpt_to,
        subject: found.subject,
        relay_queue_id: found.relay_queue_id,
        last_error: found.last_error,
        created_at: found.created_at,
        completed_at: found.completed_at,
    }))
}

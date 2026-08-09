//! One error type, one JSON shape.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    /// The caller asked for something malformed. The message is shown to
    /// them, so it says what to fix.
    BadRequest(String),
    NotFound,
    /// Authenticated, but the action needs the admin role. Distinct from
    /// 401 so the UI does not throw away a perfectly good session.
    Forbidden,
    /// The admin surface was called but ADMIN_TOKEN is not configured.
    /// Honest 503 rather than a 401 that sends someone hunting for a
    /// mistyped token that does not exist.
    AdminDisabled,
    /// Something on our side. The detail is logged, never returned — an
    /// error page is not a place to leak a connection string.
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "missing or invalid API key".to_string(),
            ),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Forbidden => (
                StatusCode::FORBIDDEN,
                "this action requires the admin role".to_string(),
            ),
            ApiError::AdminDisabled => (
                StatusCode::SERVICE_UNAVAILABLE,
                "admin surface is not configured (ADMIN_TOKEN is unset)".to_string(),
            ),
            ApiError::Internal(err) => {
                eprintln!("postbud: internal error: {err:#}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::Internal(err)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

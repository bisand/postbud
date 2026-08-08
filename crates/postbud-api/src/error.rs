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

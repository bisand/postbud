//! Tenant authentication.
//!
//! One seam. Adding [`Tenant`] as a handler argument is what protects a
//! route, so no endpoint can be added that forgets to authenticate — the
//! same trick regnmed uses with its `AuthPerson` extractor.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use postbud_db::tenant;

use crate::AppState;
use crate::error::ApiError;

/// An authenticated tenant. Carries the sending domains it is allowed to
/// use, so the authorization check has everything it needs without a
/// second lookup.
#[derive(Debug, Clone)]
pub struct Tenant(pub tenant::Tenant);

impl FromRequestParts<AppState> for Tenant {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let key = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?
            .trim();

        let tenant = tenant::by_api_key(&state.pool, key)
            .await
            .map_err(ApiError::Internal)?
            .ok_or(ApiError::Unauthorized)?;

        Ok(Tenant(tenant))
    }
}

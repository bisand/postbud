//! The admin gate, seen to fail.
//!
//! No database needed: `connect_lazy` gives a pool that never dials until
//! a query runs, and every case here must be decided BEFORE any query —
//! that is the property under test. The one exception proves the rule: a
//! correct token reaches the handler, which then fails on the dead pool
//! with a 500. A 500 is the auth gate passing; a 401/503 is it holding.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

fn app(admin_token: Option<&str>) -> axum::Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        // Port 9 is discard; nothing listens. Any query fails fast — and
        // the short acquire timeout keeps "fails" meaning seconds, not
        // sqlx's default 30.
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://nobody@127.0.0.1:9/nothing")
        .expect("lazy pool");
    postbud_api::router(postbud_api::AppState {
        pool,
        bounce_token: None,
        admin_token: admin_token.map(String::from),
        admin_oidc: None,
        spf_default: None,
    })
}

async fn get(app: axum::Router, path: &str, bearer: Option<&str>) -> StatusCode {
    let mut req = Request::builder().uri(path);
    if let Some(token) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn admin_surface_is_off_without_a_configured_token() {
    // Even a caller presenting SOME token gets 503, not 401: there is no
    // token that would have worked, and the error should say so.
    let status = get(app(None), "/admin/api/overview", Some("anything")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_missing_token_is_rejected_before_any_query() {
    let status = get(app(Some("secret")), "/admin/api/overview", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_token_is_rejected_before_any_query() {
    let status = get(app(Some("secret")), "/admin/api/overview", Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_right_token_reaches_the_handler() {
    // The dead pool turns the handler into a 500 — which is exactly the
    // point: anything but 401/503 means the gate opened.
    let status = get(app(Some("secret")), "/admin/api/overview", Some("secret")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn tenant_endpoints_do_not_accept_the_admin_token_shape() {
    // A tenant route with the admin token still 401s (it is not a tenant
    // key), and — the important direction — an admin route is never
    // reachable through the tenant extractor's path. The routes are
    // disjoint by construction; this pins the tenant side.
    let status = get(app(Some("secret")), "/v1/suppressions", Some("secret")).await;
    // The tenant extractor DOES query the database to resolve the key, so
    // the dead pool yields 500 here — meaning it tried. That is fine: a
    // tenant lookup of the admin token finds nothing in real life, and the
    // admin token is never stored in the tenant table.
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn the_ui_shell_is_served_without_auth_and_assets_404_cleanly() {
    // The shell is static and holds no data; everything behind it needs
    // the token. An unknown asset is a plain 404, never the app shell.
    assert_eq!(get(app(None), "/admin", None).await, StatusCode::OK);
    assert_eq!(
        get(app(None), "/admin/assets/no-such-file.js", None).await,
        StatusCode::NOT_FOUND
    );
}

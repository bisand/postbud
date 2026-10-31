//! The OIDC path through the admin gate, seen to fail.
//!
//! A real RSA keypair is generated at test time (never committed) and its
//! public half becomes a static JWKS, so signatures are validated for
//! real — the same wiring `ADMIN_OIDC_JWKS_FILE` gives a dev setup. The
//! pool is dead (`connect_lazy` at a closed port), so a 500 means the
//! gate OPENED and the handler hit the database; 401 means it held.

use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use tower::ServiceExt;

const ISSUER: &str = "https://issuer.test";
const CLIENT_ID: &str = "postbud-admin";

/// (private key PEM, JWKS json). Generated once per test process.
fn keys() -> &'static (String, String) {
    static KEYS: OnceLock<(String, String)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .expect("generating test RSA key");
        let pem = key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encoding PEM")
            .to_string();
        let jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-1","use":"sig","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        );
        (pem, jwks)
    })
}

fn app(users: &[&str], admin_token: Option<&str>) -> axum::Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://nobody@127.0.0.1:9/nothing")
        .expect("lazy pool");
    let oidc = postbud_api::oidc::OidcAdmin::with_static_jwks(ISSUER, CLIENT_ID, users, &keys().1)
        .expect("building OidcAdmin");
    postbud_api::router(postbud_api::AppState {
        pool,
        bounce_token: None,
        admin_token: admin_token.map(String::from),
        admin_oidc: Some(oidc),
        spf_default: None,
    })
}

fn sign(claims: serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-1".into());
    let key = EncodingKey::from_rsa_pem(keys().0.as_bytes()).expect("loading signing key");
    encode(&header, &claims, &key).expect("signing token")
}

fn token(iss: &str, aud: &str, email: &str, exp_offset_secs: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    sign(serde_json::json!({
        "iss": iss,
        "aud": aud,
        "sub": "user-42",
        "email": email,
        "exp": now + exp_offset_secs,
        "iat": now,
    }))
}

async fn get(app: axum::Router, bearer: &str) -> StatusCode {
    app.oneshot(
        Request::builder()
            .uri("/admin/api/overview")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn a_validly_signed_token_reaches_the_authorization_stage() {
    // Authorization now lives in the admin-user table, so a valid token
    // proceeds to the database — which is dead here. 500 = the signature,
    // issuer, audience and expiry all passed; the refusal/authorization
    // paths themselves are covered by the DB-backed tests
    // (admin_roles_db) and by the pure allowlist tests below.
    let t = token(ISSUER, CLIENT_ID, "admin@example.com", 300);
    let status = get(app(&["admin@example.com"], None), &t).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_token_for_another_client_is_refused() {
    // Same issuer, same user, wrong audience: an id_token minted for a
    // DIFFERENT application must not open this one.
    let t = token(ISSUER, "some-other-app", "admin@example.com", 300);
    let status = get(app(&["admin@example.com"], None), &t).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_from_another_issuer_is_refused() {
    let t = token("https://evil.example", CLIENT_ID, "admin@example.com", 300);
    let status = get(app(&["admin@example.com"], None), &t).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let t = token(ISSUER, CLIENT_ID, "admin@example.com", -3600);
    let status = get(app(&["admin@example.com"], None), &t).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn garbage_is_refused() {
    let status = get(app(&["admin@example.com"], None), "not-a-jwt").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_static_token_still_works_beside_oidc() {
    // The break-glass property: an issuer outage must not lock the
    // operator out of their own mail admin.
    let status = get(app(&["admin@example.com"], Some("secret")), "secret").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// The BOOTSTRAP allowlist's matching rules, tested pure: email is
/// case-insensitive, subject id is exact. (It only governs while the
/// admin-user table is empty; the api-level behavior is covered in
/// admin_roles_db.)
#[tokio::test]
async fn env_allowlist_matches_email_case_insensitively_and_sub_exactly() {
    let oidc = postbud_api::oidc::OidcAdmin::with_static_jwks(
        ISSUER,
        CLIENT_ID,
        &["admin@example.com", "user-42"],
        &keys().1,
    )
    .unwrap();

    let id = |sub: &str, email: Option<&str>| postbud_api::oidc::Identity {
        sub: sub.into(),
        email: email.map(String::from),
    };

    assert!(oidc.env_allowlisted(&id("x", Some("Admin@Example.COM"))));
    assert!(oidc.env_allowlisted(&id("user-42", None)));
    assert!(!oidc.env_allowlisted(&id("USER-42", None)), "sub is exact");
    assert!(!oidc.env_allowlisted(&id("y", Some("other@example.com"))));
}

// ------------------------------------------- the refresh token's cookie

/// A stand-in for the issuer that ROTATES, and reissues an id_token from
/// the refresh grant: a refresh token can be spent exactly once, and the
/// answer carries its replacement.
///
/// Both halves now match the issuer deployed against -- but the id_token
/// did not when these tests were written, and they passed anyway. The
/// mock was modelled on a sibling project's, whose portal authenticates
/// with the access token and so never needed that field, so it answered
/// the refresh grant with an id_token while the real issuer did not, and
/// the keep-alive shipped unable to work (docs/architecture.md §9).
/// The lesson is in what these tests are FOR: the SERVER's half of the
/// contract -- the refresh token never reaching the page, the
/// replacement reaching the cookie, reuse refused without leaking the
/// issuer's detail. A mock cannot settle the end-to-end session,
/// because a mock is written from the same belief as the code.
/// Serves discovery too, so `oidc.discovery()` finds the
/// token endpoint the way it does in production — nothing is hardcoded.
/// Returns the base URL.
async fn mock_issuer() -> String {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    // The tokens still alive, and a counter so an id_token is never
    // named after the refresh token that bought it — otherwise asserting
    // "the refresh token is not in the body" matches its own substring.
    let live: Arc<Mutex<(usize, HashSet<String>)>> = Arc::new(Mutex::new((0, HashSet::new())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());

    let discovery = base.clone();
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let base = discovery.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": format!("{base}/token"),
                        "jwks_uri": format!("{base}/jwks"),
                    }))
                }
            }),
        )
        .route(
            "/token",
            axum::routing::post(move |form: String| {
                let live = live.clone();
                async move {
                    let field = |name: &str| {
                        form.split('&')
                            .find_map(|p| p.strip_prefix(&format!("{name}=")))
                            .unwrap_or_default()
                            .to_string()
                    };
                    let mint = || {
                        let mut live = live.lock().unwrap();
                        live.0 += 1;
                        let n = live.0;
                        live.1.insert(format!("r{n}"));
                        (
                            StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "access_token": format!("at{n}"),
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "refresh_token": format!("r{n}"),
                                "id_token": format!("idt{n}"),
                            })),
                        )
                    };
                    match field("grant_type").as_str() {
                        // The login: the issuer hands out the first
                        // refresh token here, where the cookie is born.
                        "authorization_code" => mint(),
                        "refresh_token" => {
                            let spent = field("refresh_token");
                            if !live.lock().unwrap().1.remove(&spent) {
                                // The detail a reused token produces at
                                // the issuer — it must never reach the
                                // browser.
                                return (
                                    StatusCode::BAD_REQUEST,
                                    axum::Json(serde_json::json!({
                                        "error": "invalid_grant",
                                        "error_description":
                                            format!("refresh token already used: {spent}"),
                                    })),
                                );
                            }
                            mint()
                        }
                        _ => (
                            StatusCode::BAD_REQUEST,
                            axum::Json(serde_json::json!({"error": "unsupported_grant_type"})),
                        ),
                    }
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

/// The same router as [`app`], but pointed at a live mock issuer so the
/// token-endpoint proxy can be exercised end to end.
fn app_against(issuer: &str, admin_token: Option<&str>) -> axum::Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect_lazy("postgres://nobody@127.0.0.1:9/nothing")
        .expect("lazy pool");
    let oidc = postbud_api::oidc::OidcAdmin::with_static_jwks(issuer, CLIENT_ID, &[], &keys().1)
        .expect("building OidcAdmin");
    postbud_api::router(postbud_api::AppState {
        pool,
        bounce_token: None,
        admin_token: admin_token.map(String::from),
        admin_oidc: Some(oidc),
        spf_default: None,
    })
}

/// POSTs one of the OIDC proxy routes (no bearer — these run before
/// there is a token) and returns the status, the Set-Cookie and the body.
async fn post_oidc(
    app: axum::Router,
    uri: &str,
    cookie: Option<&str>,
    forwarded_proto: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, String, String) {
    let mut request = Request::builder().method("POST").uri(uri);
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    if let Some(proto) = forwarded_proto {
        request = request.header("x-forwarded-proto", proto);
    }
    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (
        status,
        set_cookie,
        String::from_utf8_lossy(&bytes).to_string(),
    )
}

/// THE security property of the whole flow: the long-lived refresh token
/// never reaches the page. It leaves this server only as an HttpOnly
/// cookie, so an XSS can spend the id_token already running and cannot
/// mint itself another session.
///
/// And the usability property it buys: an expired id_token no longer
/// means a new login — the refresh route spends the cookie and rotates
/// it.
#[tokio::test]
async fn the_refresh_token_leaves_only_as_an_httponly_cookie() {
    let issuer = mock_issuer().await;

    // Nothing to renew before anyone has logged in, and saying so with
    // 401 rather than 400 is what stops the browser from retrying.
    let (status, _, _) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/refresh",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The login. The issuer returns a refresh token; the browser must not.
    let (status, cookie, body) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/token",
        None,
        None,
        Some(serde_json::json!({
            "code": "c",
            "code_verifier": "v",
            "redirect_uri": "http://admin.test/admin",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains("refresh_token") && !body.contains("r1"),
        "the refresh token reached the page: {body}"
    );
    assert!(body.contains("idt1"), "{body}");
    for attribute in [
        "postbud_admin_refresh=r1",
        "HttpOnly",
        "SameSite=Strict",
        // Only the two routes that spend it ever see it.
        "Path=/admin/api/oidc",
        "Max-Age=43200",
    ] {
        assert!(cookie.contains(attribute), "{attribute} missing: {cookie}");
    }
    // Plain HTTP on a private network is a legitimate deployment here,
    // and a Secure cookie would never be stored — nobody could log in.
    assert!(!cookie.contains("Secure"), "{cookie}");

    // Twelve hours later: the cookie buys a new id_token, and ROTATES.
    let (status, rotated, body) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/refresh",
        Some("postbud_admin_refresh=r1"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("idt2"), "{body}");
    assert!(!body.contains("refresh_token"), "{body}");
    assert!(
        rotated.contains("postbud_admin_refresh=r2"),
        "the replacement must reach the browser, or the session dies \
         when the id_token expires with nothing in any log to say why: {rotated}"
    );

    // Spending the same token twice is what two tabs racing does. The
    // issuer refuses it, and its own detail stays server-side.
    let (status, _, body) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/refresh",
        Some("postbud_admin_refresh=r1"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains("invalid_grant"), "{body}");
    assert!(!body.contains("already used"), "{body}");
    assert!(!body.contains("r1"), "{body}");

    // Logout drops the cookie. Without this the next visit on a shared
    // machine signs the previous user back in.
    let (status, cookie, _) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/logout",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(cookie.contains("Max-Age=0"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
}

/// `Secure` is set when the request actually arrived over TLS, and only
/// then. Unconditionally would be stronger — and would make login
/// impossible on the plain-HTTP private-network deployment this service
/// supports, because the browser would simply not store the cookie.
#[tokio::test]
async fn the_cookie_is_secure_exactly_when_the_request_was() {
    let issuer = mock_issuer().await;
    let login = serde_json::json!({
        "code": "c",
        "code_verifier": "v",
        "redirect_uri": "https://admin.test/admin",
    });
    let (_, cookie, _) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/token",
        None,
        Some("https"),
        Some(login.clone()),
    )
    .await;
    assert!(cookie.contains("Secure"), "{cookie}");

    // A proxy that terminates TLS elsewhere and forwards plain http.
    let (_, cookie, _) = post_oidc(
        app_against(&issuer, None),
        "/admin/api/oidc/token",
        None,
        Some("http"),
        Some(login),
    )
    .await;
    assert!(!cookie.contains("Secure"), "{cookie}");
}

/// The break-glass path is untouched: `ADMIN_TOKEN` is a static
/// credential with no refresh behind it, so it must neither acquire a
/// cookie nor be logged out by any of the above. A session with it has
/// no cookie, the refresh route answers 401, the browser does not retry,
/// and the behaviour is exactly what it was before.
#[tokio::test]
async fn an_admin_token_session_has_no_cookie_and_is_not_logged_out() {
    let issuer = mock_issuer().await;
    let response = app_against(&issuer, Some("break-glass"))
        .oneshot(
            Request::builder()
                .uri("/admin/api/overview")
                .header(header::AUTHORIZATION, "Bearer break-glass")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // 500 = the gate OPENED and the handler reached the dead database.
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "the break-glass path must not mint a session cookie"
    );

    // And asking to refresh it is an honest "there is no session here",
    // not a retry-worthy failure.
    let (status, cookie, _) = post_oidc(
        app_against(&issuer, Some("break-glass")),
        "/admin/api/oidc/refresh",
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie.is_empty(), "{cookie}");
}

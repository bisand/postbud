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

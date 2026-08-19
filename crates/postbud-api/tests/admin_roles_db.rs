//! The role gate through real HTTP against a real database.
//!
//! Skips politely without DATABASE_URL. This is the test the DB-free
//! gate tests cannot be: a VIEWER's valid, signed login reading freely
//! and being refused every mutation with 403 — not 401, the session is
//! fine — while an admin's passes.

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

fn keys() -> (String, String) {
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("test RSA key");
    let pem = key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("PEM")
        .to_string();
    let jwks = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"test-1","use":"sig","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
        URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    );
    (pem, jwks)
}

fn token(pem: &str, email: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-1".into());
    let now = chrono::Utc::now().timestamp();
    encode(
        &header,
        &serde_json::json!({
            "iss": ISSUER, "aud": CLIENT_ID, "sub": format!("sub-{email}"),
            "email": email, "exp": now + 300, "iat": now,
        }),
        &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("signing key"),
    )
    .expect("signing")
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    bearer: &str,
    body: Option<&str>,
) -> StatusCode {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    if body.is_some() {
        req = req.header(header::CONTENT_TYPE, "application/json");
    }
    app.clone()
        .oneshot(
            req.body(body.map(|b| Body::from(b.to_string())).unwrap_or_default())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_viewer_reads_everything_and_changes_nothing() {
    dotenvy::dotenv().ok();
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let pool = postbud_db::connect(&url).await.expect("connecting");
    postbud_db::migrate(&pool).await.expect("migrating");

    let (pem, jwks) = keys();
    let oidc = postbud_api::oidc::OidcAdmin::with_static_jwks(ISSUER, CLIENT_ID, &[], &jwks)
        .expect("OidcAdmin");
    let app = postbud_api::router(postbud_api::AppState {
        pool: pool.clone(),
        bounce_token: None,
        admin_token: Some("bootstrap-token".into()),
        admin_oidc: Some(oidc),
        spf_default: None,
    });

    // Unique identities per run: the shared dev database must not make
    // two runs of this test collide.
    let run = uuid::Uuid::new_v4().simple().to_string();
    let viewer_mail = format!("viewer-{run}@example.com");
    let admin_mail = format!("admin-{run}@example.com");

    // Bootstrap through the API itself, with the static token — exactly
    // how a real installation seeds its first users.
    for (mail, role) in [(&admin_mail, "admin"), (&viewer_mail, "viewer")] {
        let status = call(
            &app,
            "POST",
            "/admin/api/users",
            "bootstrap-token",
            Some(&format!(r#"{{"identifier":"{mail}","role":"{role}"}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "seeding {role}");
    }

    let viewer = token(&pem, &viewer_mail);
    let admin = token(&pem, &admin_mail);

    // The viewer reads freely...
    for path in [
        "/admin/api/overview",
        "/admin/api/messages",
        "/admin/api/suppressions",
        "/admin/api/tenants",
        "/admin/api/bounces",
        "/admin/api/users",
        "/admin/api/me",
        // The DMARC surface is read-only for EVERY role -- there is no
        // mutating counterpart below, and there must never be one: a
        // report is an unauthenticated claim by a stranger.
        "/admin/api/dmarc",
        "/admin/api/dmarc/example.com",
    ] {
        let status = call(&app, "GET", path, &viewer, None).await;
        assert_eq!(status, StatusCode::OK, "viewer reading {path}");
    }

    // ...and changes nothing: 403 everywhere, never 401 — the session is
    // valid, the role is insufficient.
    let mutations = [
        (
            "POST",
            "/admin/api/suppressions".to_string(),
            Some(r#"{"address":"x@example.com"}"#.to_string()),
        ),
        ("DELETE", "/admin/api/suppressions/1".to_string(), None),
        (
            "POST",
            "/admin/api/tenants".to_string(),
            Some(r#"{"name":"x","from_domains":["example.com"]}"#.to_string()),
        ),
        (
            "POST",
            "/admin/api/users".to_string(),
            Some(r#"{"identifier":"y@example.com","role":"viewer"}"#.to_string()),
        ),
        ("DELETE", "/admin/api/users/1".to_string(), None),
    ];
    for (method, path, body) in &mutations {
        let status = call(&app, method, path, &viewer, body.as_deref()).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "viewer must not {method} {path}"
        );
    }

    // The admin's identical call goes through.
    let status = call(
        &app,
        "POST",
        "/admin/api/suppressions",
        &admin,
        Some(&format!(r#"{{"address":"blockme-{run}@example.com"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // And the audit trail carries the admin's NAME, not "admin".
    let source: String = sqlx::query_scalar(
        "select source from suppression where address = $1 and removed_at is null",
    )
    .bind(format!("blockme-{run}@example.com"))
    .fetch_one(&pool)
    .await
    .expect("reading the suppression row");
    assert_eq!(source, admin_mail);

    // A validly signed login for someone in NO role is refused outright —
    // the issuer vouched for the identity, but nobody granted it
    // anything, and the table being non-empty means the bootstrap
    // allowlist no longer applies.
    let stranger = token(&pem, &format!("stranger-{run}@example.com"));
    let status = call(&app, "GET", "/admin/api/overview", &stranger, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

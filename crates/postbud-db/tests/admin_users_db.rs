//! The admin-user table's rules, against a real Postgres.
//!
//! Skips politely when DATABASE_URL is unset; runs for real in CI. One
//! sequential test on purpose: the last-admin rule is a statement about
//! the WHOLE table, so the table is cleared first and the steps must not
//! interleave with each other.

use postbud_db::admin_user;

async fn pool() -> Option<sqlx::PgPool> {
    dotenvy::dotenv().ok();
    postbud_db::testsupport::pool_or_skip("admin_users_db").await
}

#[tokio::test]
async fn the_grant_lifecycle_and_the_last_admin_rule() {
    let Some(pool) = pool().await else { return };
    sqlx::query("delete from admin_user")
        .execute(&pool)
        .await
        .expect("clearing table for the scenario");

    // Empty table: nobody resolves, and the bootstrap window is open.
    let (role, any) = admin_user::resolve(&pool, "nobody", None).await.unwrap();
    assert_eq!(role, None);
    assert!(!any, "empty table must report no active rows");

    // First admin. The bootstrap window closes with this row.
    let a = admin_user::add(&pool, "Admin@Example.com", "admin", None, "test")
        .await
        .expect("adding first admin");

    // A duplicate active grant is refused by name, case-insensitively.
    let err = admin_user::add(&pool, "admin@EXAMPLE.com", "viewer", None, "test")
        .await
        .expect_err("duplicate must be refused");
    assert!(err.to_string().contains("already has an active grant"));

    // Resolution: email case-insensitive, and the window is now closed.
    let (role, any) = admin_user::resolve(&pool, "some-sub", Some("ADMIN@example.COM"))
        .await
        .unwrap();
    assert_eq!(role.as_deref(), Some("admin"));
    assert!(any);

    // A viewer, resolved by exact subject id.
    let v = admin_user::add(&pool, "user-42", "viewer", Some("ops"), "test")
        .await
        .unwrap();
    let (role, _) = admin_user::resolve(&pool, "user-42", None).await.unwrap();
    assert_eq!(role.as_deref(), Some("viewer"));

    // The last admin can be neither removed nor demoted — a viewer
    // existing does not count.
    let err = admin_user::end(&pool, a.id, "test")
        .await
        .expect_err("last admin");
    assert!(err.to_string().contains("last admin"));
    let err = admin_user::set_role(&pool, a.id, "viewer", "test")
        .await
        .expect_err("demoting last admin");
    assert!(err.to_string().contains("last admin"));

    // Promote the viewer; the original admin can then retire.
    assert!(
        admin_user::set_role(&pool, v.id, "admin", "test")
            .await
            .unwrap()
    );
    assert!(admin_user::end(&pool, a.id, "test").await.unwrap());

    // The promoted user resolves as admin under a NEW row (the role
    // change was an end + an insert, not an edit).
    let (role, _) = admin_user::resolve(&pool, "user-42", None).await.unwrap();
    assert_eq!(role.as_deref(), Some("admin"));

    // History: everything that happened is still visible.
    let history = admin_user::list(&pool, true).await.unwrap();
    let ended = history.iter().filter(|u| u.ended_at.is_some()).count();
    assert_eq!(ended, 2, "the retired admin and the viewer's old grant");
    let active = admin_user::list(&pool, false).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].identifier, "user-42");
    assert_eq!(active[0].created_by, "test");
}

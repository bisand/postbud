//! Getting a database for the workspace's DB-backed tests, or honestly
//! not getting one.
//!
//! One source, used from every DB-backed test in the workspace, because
//! the decision it makes must not differ between them: whether a missing
//! database means "skip" or "fail" is a property of the RUN, not of the
//! test that happened to ask first.
//!
//! The rule it encodes is the interesting part. A developer without
//! Postgres running should get a fast, clear skip rather than a suite
//! that hangs and then fails for a reason that has nothing to do with
//! their change. But CI HAS a database, so a skip there is not politeness
//! -- it is the suite quietly shrinking to the tests that need nothing,
//! passing green while the half that touches the schema never ran. So in
//! CI, no database is a failure, loudly.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

/// Long enough for a container still waking up, short enough that a
/// developer with nothing listening is not left watching a cursor. The
/// default is thirty seconds, which is neither.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A pool with migrations applied, or `None` when this run has no
/// database and is allowed not to.
///
/// `what` names the caller, so a skipped run says which tests it skipped
/// rather than leaving one anonymous line in a wall of output.
///
/// Reading `.env` is left to the caller. It belongs in the test files,
/// where dotenvy is already a dev-dependency — pulling it in here would
/// put a .env reader into the production library for the sake of test
/// scaffolding. Note what that loading does, though: with a DATABASE_URL
/// in .env the "unset" branch is nearly unreachable in this repository,
/// which is exactly how a skip came to be written, believed in, and never
/// once taken.
pub async fn pool_or_skip(what: &str) -> Option<PgPool> {
    let in_ci = std::env::var("CI").is_ok_and(|v| !v.is_empty());

    let Ok(url) = std::env::var("DATABASE_URL") else {
        return skip_or_fail(what, in_ci, "DATABASE_URL is not set");
    };

    let pool = match PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect(&url)
        .await
    {
        Ok(pool) => pool,
        // A URL that points at nothing is the same situation as no URL:
        // this run cannot test the database. Distinguishing them would
        // only make one of the two hang for thirty seconds first.
        Err(e) => return skip_or_fail(what, in_ci, &format!("cannot reach the database: {e}")),
    };

    // Failing rather than skipping: a database we CAN reach and cannot
    // migrate is a broken schema, which is a result, not an absence.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("running migrations");
    Some(pool)
}

fn skip_or_fail(what: &str, in_ci: bool, why: &str) -> Option<PgPool> {
    if in_ci {
        panic!(
            "{what}: {why}. CI has a database, so this is not something to skip past — \
             a green run that silently dropped its DB-backed tests is worse than a red one."
        );
    }
    eprintln!("skipping {what}: {why}");
    None
}

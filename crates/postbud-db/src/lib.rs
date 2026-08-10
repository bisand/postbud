//! PostgreSQL persistence.
//!
//! Queries use sqlx's runtime API rather than the `query!` macros: a
//! build must not require a live database.
//!
//! Note the split of responsibility this crate encodes. postbud owns the
//! queue, the suppression list and the delivery record. It does NOT own
//! delivery itself — no MX resolution, no per-destination concurrency, no
//! TLS policy, no DSN generation. That is Postfix's job, and reimplementing
//! it in Rust would be trading decades of edge cases for a weekend.

pub mod admin;
pub mod admin_user;
pub mod bounce;
pub mod domain;
pub mod message;
pub mod relay;
pub mod suppression;
pub mod tenant;

use anyhow::Context;
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Connect. The pool is small on purpose: transactional-mail load is a
/// handful of messages a minute, and the whole system is built to fit a
/// small VM.
///
/// `DATABASE_MAX_CONNECTIONS` raises it for a process that needs more. The
/// worker is the one that does: it holds one connection permanently for
/// queue notifications, and each in-flight delivery wants one briefly to
/// write its outcome — so the ceiling must clear `WORKER_CONCURRENCY + 1`,
/// or deliveries queue behind each other at the very last step.
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let max = std::env::var("DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(8);

    PgPoolOptions::new()
        .max_connections(max)
        .connect(database_url)
        .await
        .context("connecting to Postgres")
}

/// Apply migrations. Embedded at compile time, so the binary carries its
/// own schema and a deploy needs no separate file copy.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("running migrations")?;
    Ok(())
}

//! PostgreSQL persistence.
//!
//! Queries use sqlx's runtime API rather than the `query!` macros, for the
//! same reason regnmed does: a build must not require a live database.
//!
//! Note the split of responsibility this crate encodes. postbud owns the
//! queue, the suppression list and the delivery record. It does NOT own
//! delivery itself — no MX resolution, no per-destination concurrency, no
//! TLS policy, no DSN generation. That is Postfix's job, and reimplementing
//! it in Rust would be trading decades of edge cases for a weekend.

pub mod admin;
pub mod bounce;
pub mod message;
pub mod suppression;
pub mod tenant;

use anyhow::Context;
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Connect. The pool is small on purpose: postbud's load is a handful of
/// messages a minute, and the frugality budget is the same one regnmed
/// holds itself to.
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(8)
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

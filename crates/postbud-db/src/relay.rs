//! The relay's own verification history.
//!
//! Insert-only, for the same reason as `domain_check`: a mutable status
//! column can say what is wrong now, and never when it broke or for how
//! long. There is one relay by design, so there is no registry here —
//! the expected host is configuration, recorded ON each row so a check
//! from before a rename stays readable as a statement about the name in
//! force at the time.

use anyhow::Context;
use chrono::{DateTime, Utc};
use postbud_core::rdns::RelayResult;
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RelayCheckRow {
    pub checked_at: DateTime<Utc>,
    pub expected_host: String,
    pub forward_status: String,
    pub forward_observed: Option<String>,
    pub ptr_status: String,
    pub ptr_observed: Option<String>,
    pub helo_status: Option<String>,
    pub helo_observed: Option<String>,
    pub valid: bool,
}

fn row_to_check(r: sqlx::postgres::PgRow) -> RelayCheckRow {
    RelayCheckRow {
        checked_at: r.get("checked_at"),
        expected_host: r.get("expected_host"),
        forward_status: r.get("forward_status"),
        forward_observed: r.get("forward_observed"),
        ptr_status: r.get("ptr_status"),
        ptr_observed: r.get("ptr_observed"),
        helo_status: r.get("helo_status"),
        helo_observed: r.get("helo_observed"),
        valid: r.get("valid"),
    }
}

pub async fn record_check(
    pool: &PgPool,
    expected_host: &str,
    result: &RelayResult,
) -> anyhow::Result<()> {
    sqlx::query(
        "insert into relay_check
             (expected_host, forward_status, forward_observed,
              ptr_status, ptr_observed, helo_status, helo_observed, valid)
         values ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(expected_host)
    .bind(result.forward.status.as_str())
    .bind(&result.forward.observed)
    .bind(result.ptr.status.as_str())
    .bind(&result.ptr.observed)
    .bind(result.helo.as_ref().map(|h| h.status.as_str()))
    .bind(result.helo.as_ref().and_then(|h| h.observed.clone()))
    .bind(result.valid)
    .execute(pool)
    .await
    .context("recording relay check")?;
    Ok(())
}

/// The current state, or None when no check has run yet — a fresh
/// installation, or one whose relay host is not configured.
pub async fn latest(pool: &PgPool) -> anyhow::Result<Option<RelayCheckRow>> {
    let row = sqlx::query(
        "select checked_at, expected_host, forward_status, forward_observed,
                ptr_status, ptr_observed, helo_status, helo_observed, valid
           from relay_check order by id desc limit 1",
    )
    .fetch_optional(pool)
    .await
    .context("loading latest relay check")?;
    Ok(row.map(row_to_check))
}

/// Whether a check is due, on the same cadence as the domain checks:
/// often while something is wrong, rarely once everything is right.
pub async fn due(
    pool: &PgPool,
    recheck_minutes: i64,
    revalidate_hours: i64,
) -> anyhow::Result<bool> {
    let row = sqlx::query("select checked_at, valid from relay_check order by id desc limit 1")
        .fetch_optional(pool)
        .await
        .context("checking whether a relay check is due")?;

    let Some(row) = row else { return Ok(true) };
    let checked_at: DateTime<Utc> = row.get("checked_at");
    let valid: bool = row.get("valid");

    let age = Utc::now() - checked_at;
    Ok(if valid {
        age > chrono::Duration::hours(revalidate_hours)
    } else {
        age > chrono::Duration::minutes(recheck_minutes)
    })
}

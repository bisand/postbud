//! The suppression list — the thing Postfix cannot keep for us.

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Entry {
    pub id: i64,
    pub tenant_id: Option<Uuid>,
    pub address: String,
    pub reason: String,
    pub source: String,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Is this address suppressed for this tenant?
///
/// A row with a null `tenant_id` is global and applies to everyone: a hard
/// bounce is a fact about the mailbox, not about who happened to be writing
/// to it, so one product learning an address is dead protects the other's
/// reputation too.
pub async fn is_suppressed_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    address: &str,
) -> anyhow::Result<bool> {
    let row = sqlx::query(
        "select 1 as hit from suppression
          where lower(address) = lower($1)
            and removed_at is null
            and (tenant_id is null or tenant_id = $2)
          limit 1",
    )
    .bind(address)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .context("checking suppression list")?;
    Ok(row.is_some())
}

/// Add an address. Idempotent: re-suppressing an already-suppressed
/// address is a no-op rather than an error, because the bounce ingester
/// will legitimately see the same dead address many times.
pub async fn add(
    pool: &PgPool,
    tenant_id: Option<Uuid>,
    address: &str,
    reason: &str,
    source: &str,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "insert into suppression (tenant_id, address, reason, source, detail)
              values ($1, $2, $3, $4, $5)
         on conflict do nothing",
    )
    .bind(tenant_id)
    .bind(address)
    .bind(reason)
    .bind(source)
    .bind(detail)
    .execute(pool)
    .await
    .context("adding suppression")?;
    Ok(())
}

/// Lift a suppression.
///
/// A soft delete, deliberately. "Suppressed on the 3rd, lifted by André on
/// the 9th" is exactly the history someone needs when a customer reports
/// they stopped receiving invoices; a hard delete answers nothing.
pub async fn remove(pool: &PgPool, id: i64, removed_by: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "update suppression
            set removed_at = now(), removed_by = $2
          where id = $1 and removed_at is null",
    )
    .bind(id)
    .bind(removed_by)
    .execute(pool)
    .await
    .context("removing suppression")?;
    Ok(result.rows_affected() > 0)
}

/// Active suppressions visible to a tenant: its own plus the global ones.
pub async fn list(
    pool: &PgPool,
    tenant_id: Uuid,
    address_filter: Option<&str>,
) -> anyhow::Result<Vec<Entry>> {
    let rows = sqlx::query(
        "select id, tenant_id, address, reason, source, detail, created_at
           from suppression
          where removed_at is null
            and (tenant_id is null or tenant_id = $1)
            and ($2::text is null or lower(address) = lower($2))
          order by created_at desc
          limit 500",
    )
    .bind(tenant_id)
    .bind(address_filter)
    .fetch_all(pool)
    .await
    .context("listing suppressions")?;

    Ok(rows
        .into_iter()
        .map(|r| Entry {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            address: r.get("address"),
            reason: r.get("reason"),
            source: r.get("source"),
            detail: r.get("detail"),
            created_at: r.get("created_at"),
        })
        .collect())
}

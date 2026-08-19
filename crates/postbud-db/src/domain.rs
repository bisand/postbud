//! The sending-domain registry and its verification history.

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use postbud_core::dnscheck::DomainResult;
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, serde::Serialize)]
pub struct SendingDomain {
    pub id: i64,
    pub domain: String,
    pub spf_expected: String,
    pub dkim_selector: String,
    pub dkim_public_key: String,
    pub mx_expected: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

fn row_to_domain(r: sqlx::postgres::PgRow) -> SendingDomain {
    SendingDomain {
        id: r.get("id"),
        domain: r.get("domain"),
        spf_expected: r.get("spf_expected"),
        dkim_selector: r.get("dkim_selector"),
        dkim_public_key: r.get("dkim_public_key"),
        mx_expected: r.get("mx_expected"),
        created_at: r.get("created_at"),
        created_by: r.get("created_by"),
    }
}

pub async fn list(pool: &PgPool) -> anyhow::Result<Vec<SendingDomain>> {
    let rows = sqlx::query(
        "select id, domain, spf_expected, dkim_selector, dkim_public_key,
                mx_expected, created_at, created_by
           from sending_domain
          where ended_at is null
          order by lower(domain)",
    )
    .fetch_all(pool)
    .await
    .context("listing sending domains")?;
    Ok(rows.into_iter().map(row_to_domain).collect())
}

pub async fn by_id(pool: &PgPool, id: i64) -> anyhow::Result<Option<SendingDomain>> {
    let row = sqlx::query(
        "select id, domain, spf_expected, dkim_selector, dkim_public_key,
                mx_expected, created_at, created_by
           from sending_domain
          where id = $1 and ended_at is null",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("loading sending domain")?;
    Ok(row.map(row_to_domain))
}

#[allow(clippy::too_many_arguments)]
pub async fn add(
    pool: &PgPool,
    domain: &str,
    spf_expected: &str,
    dkim_selector: &str,
    dkim_public_key: &str,
    mx_expected: Option<&str>,
    created_by: &str,
) -> anyhow::Result<SendingDomain> {
    let row = sqlx::query(
        "insert into sending_domain
             (domain, spf_expected, dkim_selector, dkim_public_key,
              mx_expected, created_by)
         values ($1, $2, $3, $4, $5, $6)
         returning id, domain, spf_expected, dkim_selector, dkim_public_key,
                   mx_expected, created_at, created_by",
    )
    .bind(domain)
    .bind(spf_expected)
    .bind(dkim_selector)
    .bind(dkim_public_key)
    .bind(mx_expected)
    .bind(created_by)
    .fetch_one(pool)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            anyhow!("'{domain}' is already registered")
        }
        _ => anyhow::Error::new(e).context("adding sending domain"),
    })?;
    Ok(row_to_domain(row))
}

pub async fn end(pool: &PgPool, id: i64, ended_by: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "update sending_domain set ended_at = now(), ended_by = $2
          where id = $1 and ended_at is null",
    )
    .bind(id)
    .bind(ended_by)
    .execute(pool)
    .await
    .context("ending sending domain")?;
    Ok(result.rows_affected() > 0)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckRow {
    pub checked_at: DateTime<Utc>,
    pub spf_status: String,
    pub spf_observed: Option<String>,
    pub dkim_status: String,
    pub dkim_observed: Option<String>,
    pub dmarc_status: String,
    pub dmarc_observed: Option<String>,
    pub mx_status: Option<String>,
    pub mx_observed: Option<String>,
    /// Null when the DMARC record names no external report destination.
    pub report_auth_status: Option<String>,
    pub report_auth_observed: Option<String>,
    /// Null when the domain expects no MX (so receives no bounces), or
    /// when the relay could not be reached to ask.
    pub bounce_status: Option<String>,
    pub bounce_observed: Option<String>,
    pub valid: bool,
}

/// Record a check result. Insert-only: history, not state.
pub async fn record_check(
    pool: &PgPool,
    domain_id: i64,
    result: &DomainResult,
) -> anyhow::Result<()> {
    sqlx::query(
        "insert into domain_check
             (domain_id, spf_status, spf_observed, dkim_status, dkim_observed,
              dmarc_status, dmarc_observed, mx_status, mx_observed,
              report_auth_status, report_auth_observed, valid,
              bounce_status, bounce_observed)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(domain_id)
    .bind(result.spf.status.as_str())
    .bind(&result.spf.observed)
    .bind(result.dkim.status.as_str())
    .bind(&result.dkim.observed)
    .bind(result.dmarc.status.as_str())
    .bind(&result.dmarc.observed)
    .bind(result.mx.as_ref().map(|m| m.status.as_str()))
    .bind(result.mx.as_ref().and_then(|m| m.observed.clone()))
    .bind(result.report_auth.as_ref().map(|r| r.status.as_str()))
    .bind(result.report_auth.as_ref().and_then(|r| r.observed.clone()))
    .bind(result.valid)
    .bind(result.bounce.as_ref().map(|b| b.status.as_str()))
    .bind(result.bounce.as_ref().and_then(|b| b.observed.clone()))
    .execute(pool)
    .await
    .context("recording domain check")?;
    Ok(())
}

/// Latest check per active domain, keyed by domain id.
pub async fn latest_checks(
    pool: &PgPool,
) -> anyhow::Result<std::collections::HashMap<i64, CheckRow>> {
    let rows = sqlx::query(
        "select distinct on (domain_id)
                domain_id, checked_at, spf_status, spf_observed,
                dkim_status, dkim_observed, dmarc_status, dmarc_observed,
                mx_status, mx_observed,
                report_auth_status, report_auth_observed,
                bounce_status, bounce_observed, valid
           from domain_check
          order by domain_id, id desc",
    )
    .fetch_all(pool)
    .await
    .context("loading latest domain checks")?;

    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<i64, _>("domain_id"),
                CheckRow {
                    checked_at: r.get("checked_at"),
                    spf_status: r.get("spf_status"),
                    spf_observed: r.get("spf_observed"),
                    dkim_status: r.get("dkim_status"),
                    dkim_observed: r.get("dkim_observed"),
                    dmarc_status: r.get("dmarc_status"),
                    dmarc_observed: r.get("dmarc_observed"),
                    mx_status: r.get("mx_status"),
                    mx_observed: r.get("mx_observed"),
                    bounce_status: r.get("bounce_status"),
                    bounce_observed: r.get("bounce_observed"),
                    report_auth_status: r.get("report_auth_status"),
                    report_auth_observed: r.get("report_auth_observed"),
                    valid: r.get("valid"),
                },
            )
        })
        .collect())
}

/// Domains whose next check is due. The cadence is the feature: while
/// anything is wrong the domain is re-checked every `retry_minutes`
/// (the operator is mid-setup, feedback should be minutes away); once
/// green it drops to `revalidate_hours` (regression detection — DNS
/// also breaks later). A domain with no checks yet is always due.
pub async fn due_for_check(
    pool: &PgPool,
    retry_minutes: i64,
    revalidate_hours: i64,
) -> anyhow::Result<Vec<SendingDomain>> {
    let rows = sqlx::query(
        "select d.id, d.domain, d.spf_expected, d.dkim_selector,
                d.dkim_public_key, d.mx_expected, d.created_at, d.created_by
           from sending_domain d
           left join lateral (
                select valid, checked_at from domain_check
                 where domain_id = d.id order by id desc limit 1
           ) c on true
          where d.ended_at is null
            and (c.valid is null
                 or (not c.valid
                     and c.checked_at < now() - make_interval(mins => $1))
                 or (c.valid
                     and c.checked_at < now() - make_interval(hours => $2)))
          order by d.id",
    )
    .bind(retry_minutes as i32)
    .bind(revalidate_hours as i32)
    .fetch_all(pool)
    .await
    .context("finding domains due for a check")?;
    Ok(rows.into_iter().map(row_to_domain).collect())
}

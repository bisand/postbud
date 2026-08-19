//! Storage for DMARC aggregate reports.
//!
//! Insert-only and idempotent. See migration 0008 for why the reports are
//! kept whole and why nothing here may drive an automatic decision.

use anyhow::Context;
use chrono::{DateTime, TimeZone as _, Utc};
use postbud_core::dmarc::Report;
use sqlx::{PgPool, Row};

/// What one import run did. Duplicates are counted rather than hidden:
/// "nothing new" and "nothing found" are different answers, and only one
/// of them is a problem.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Ingested {
    pub stored: usize,
    pub duplicates: usize,
    pub records: usize,
}

/// Store one report. Returns false when this reporter's report id has
/// already been seen, which is routine rather than an error.
pub async fn store(pool: &PgPool, report: &Report, raw: &str) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await.context("beginning dmarc insert")?;

    let inserted = sqlx::query(
        "insert into dmarc_report
             (org_name, report_id, email, period_start, period_end,
              policy_domain, policy_p, policy_sp, policy_pct,
              policy_adkim, policy_aspf, raw)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         on conflict (org_name, report_id) do nothing
         returning id",
    )
    .bind(&report.org_name)
    .bind(&report.report_id)
    .bind(&report.email)
    .bind(stamp(report.begin))
    .bind(stamp(report.end))
    .bind(&report.domain)
    .bind(&report.p)
    .bind(&report.sp)
    .bind(report.pct)
    .bind(&report.adkim)
    .bind(&report.aspf)
    .bind(raw)
    .fetch_optional(&mut *tx)
    .await
    .context("storing dmarc report")?;

    let Some(row) = inserted else {
        // Already have it. Nothing to roll back, nothing to add.
        tx.rollback().await.ok();
        return Ok(false);
    };
    let report_row: i64 = row.try_get("id").context("reading dmarc report id")?;

    for record in &report.records {
        let auth = serde_json::to_value(&record.auth).context("encoding auth_results")?;
        let reasons = serde_json::to_value(&record.reasons).context("encoding reasons")?;
        sqlx::query(
            "insert into dmarc_record
                 (report, source_ip, message_count, disposition,
                  dkim_aligned, spf_aligned, header_from, auth_results, reasons)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(report_row)
        .bind(&record.source_ip)
        .bind(record.count)
        .bind(&record.disposition)
        .bind(&record.dkim_aligned)
        .bind(&record.spf_aligned)
        .bind(&record.header_from)
        .bind(auth)
        .bind(reasons)
        .execute(&mut *tx)
        .await
        .context("storing dmarc record")?;
    }

    tx.commit().await.context("committing dmarc report")?;
    Ok(true)
}

/// One domain's totals over the reports held, newest window last.
#[derive(Debug, Clone)]
pub struct DomainSummary {
    pub domain: String,
    pub reports: i64,
    pub messages: i64,
    pub passed: i64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// A roll-up for the operator, not for a decision.
pub async fn summary(pool: &PgPool) -> anyhow::Result<Vec<DomainSummary>> {
    let rows = sqlx::query(
        "select r.policy_domain                     as domain,
                count(distinct r.id)                as reports,
                -- sum() over bigint yields NUMERIC; the casts keep the
                -- decoded types matching what Rust asks for.
                coalesce(sum(d.message_count), 0)::bigint  as messages,
                coalesce(sum(d.message_count) filter (
                    where d.dkim_aligned = 'pass' or d.spf_aligned = 'pass'
                ), 0)::bigint                             as passed,
                min(r.period_start)                 as first_seen,
                max(r.period_end)                   as last_seen
           from dmarc_report r
           left join dmarc_record d on d.report = r.id
          group by r.policy_domain
          order by r.policy_domain",
    )
    .fetch_all(pool)
    .await
    .context("summarising dmarc reports")?;

    rows.into_iter()
        .map(|row| {
            Ok(DomainSummary {
                domain: row.try_get("domain")?,
                reports: row.try_get("reports")?,
                messages: row.try_get("messages")?,
                passed: row.try_get("passed")?,
                first_seen: row.try_get("first_seen")?,
                last_seen: row.try_get("last_seen")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .context("reading dmarc summary")
}

/// Reporters send UNIX seconds. A value we could not read arrives here as
/// zero, which stores as the epoch: visibly wrong in the UI rather than
/// silently shifted to now.
fn stamp(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap())
}

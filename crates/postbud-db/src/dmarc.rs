//! Storage for DMARC aggregate reports.
//!
//! Insert-only and idempotent. See migration 0008 for why the reports are
//! kept whole and why nothing here may drive an automatic decision.

use anyhow::Context;
use chrono::{DateTime, TimeZone as _, Utc};
use postbud_core::dmarc::Report;
use serde::Serialize;
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

/// One domain's totals over the reports held.
#[derive(Debug, Clone, Serialize)]
pub struct DomainSummary {
    pub domain: String,
    pub reports: i64,
    /// Distinct reporting organisations. One reporter is one receiver's
    /// opinion, and the UI says so rather than implying the internet
    /// agrees.
    pub reporters: i64,
    pub messages: i64,
    pub passed: i64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    /// The policy the most recent report saw published. Not read from
    /// DNS -- this is what a receiver says it applied.
    pub policy: Option<String>,
    /// What the reported traffic says about this domain's authentication,
    /// and whether there is enough of it to say anything.
    pub alignment: postbud_core::dmarc::Alignment,
}

/// A roll-up for the operator, not for a decision.
pub async fn summary(pool: &PgPool) -> anyhow::Result<Vec<DomainSummary>> {
    let rows = sqlx::query(
        "select r.policy_domain                     as domain,
                count(distinct r.id)                as reports,
                count(distinct r.org_name)          as reporters,
                (array_agg(r.policy_p order by r.period_start desc))[1] as policy,
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
            let messages: i64 = row.try_get("messages")?;
            let passed: i64 = row.try_get("passed")?;
            Ok(DomainSummary {
                alignment: postbud_core::dmarc::alignment(messages, passed),
                domain: row.try_get("domain")?,
                reports: row.try_get("reports")?,
                reporters: row.try_get("reporters")?,
                messages: row.try_get("messages")?,
                passed: row.try_get("passed")?,
                first_seen: row.try_get("first_seen")?,
                last_seen: row.try_get("last_seen")?,
                policy: row.try_get("policy")?,
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

/// One sending source's traffic for a domain, which is the view an
/// operator actually reads: who sent as this domain, and did it align.
#[derive(Debug, Clone, Serialize)]
pub struct SourceRollup {
    pub source_ip: String,
    pub messages: i64,
    pub passed: i64,
    /// Counted separately because WHICH mechanism carried DMARC is the
    /// whole diagnosis. A domain passing on DKIM alone is one Brevo key
    /// rotation away from failing entirely, and a total pass rate of 100%
    /// hides that completely.
    pub dkim_passed: i64,
    pub spf_passed: i64,
    pub dispositions: Vec<String>,
    /// The raw per-mechanism results from the busiest row. When an
    /// aligned result failed, this names the domain that did
    /// authenticate -- an operator staring at "spf: fail" otherwise goes
    /// hunting a broken SPF record that is perfectly fine.
    pub auth: serde_json::Value,
}

pub async fn sources(pool: &PgPool, domain: &str, days: i64) -> anyhow::Result<Vec<SourceRollup>> {
    let rows = sqlx::query(
        "select d.source_ip,
                sum(d.message_count)::bigint as messages,
                coalesce(sum(d.message_count) filter (
                    where d.dkim_aligned = 'pass' or d.spf_aligned = 'pass'
                ), 0)::bigint as passed,
                coalesce(sum(d.message_count) filter (
                    where d.dkim_aligned = 'pass'
                ), 0)::bigint as dkim_passed,
                coalesce(sum(d.message_count) filter (
                    where d.spf_aligned = 'pass'
                ), 0)::bigint as spf_passed,
                array_agg(distinct d.disposition) as dispositions,
                (array_agg(d.auth_results order by d.message_count desc))[1] as auth
           from dmarc_record d
           join dmarc_report r on r.id = d.report
          where r.policy_domain = $1
            and r.period_start >= now() - make_interval(days => $2::int)
          group by d.source_ip
          order by messages desc",
    )
    .bind(domain)
    .bind(days as i32)
    .fetch_all(pool)
    .await
    .context("rolling up dmarc sources")?;

    rows.into_iter()
        .map(|row| {
            Ok(SourceRollup {
                source_ip: row.try_get("source_ip")?,
                messages: row.try_get("messages")?,
                passed: row.try_get("passed")?,
                dkim_passed: row.try_get("dkim_passed")?,
                spf_passed: row.try_get("spf_passed")?,
                dispositions: row.try_get("dispositions")?,
                auth: row.try_get("auth")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .context("reading dmarc sources")
}

/// A day of a domain's history. One report says very little; the series
/// is the point, which is why this exists at all.
#[derive(Debug, Clone, Serialize)]
pub struct DailyPoint {
    pub day: chrono::NaiveDate,
    pub messages: i64,
    pub passed: i64,
}

pub async fn daily(pool: &PgPool, domain: &str, days: i64) -> anyhow::Result<Vec<DailyPoint>> {
    let rows = sqlx::query(
        "select r.period_start::date as day,
                sum(d.message_count)::bigint as messages,
                coalesce(sum(d.message_count) filter (
                    where d.dkim_aligned = 'pass' or d.spf_aligned = 'pass'
                ), 0)::bigint as passed
           from dmarc_record d
           join dmarc_report r on r.id = d.report
          where r.policy_domain = $1
            and r.period_start >= now() - make_interval(days => $2::int)
          group by day
          order by day",
    )
    .bind(domain)
    .bind(days as i32)
    .fetch_all(pool)
    .await
    .context("rolling up dmarc history")?;

    rows.into_iter()
        .map(|row| {
            Ok(DailyPoint {
                day: row.try_get("day")?,
                messages: row.try_get("messages")?,
                passed: row.try_get("passed")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .context("reading dmarc history")
}

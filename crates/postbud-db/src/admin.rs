//! Queries for the admin surface.
//!
//! Everything here is READ or STATE — the evidence tables (delivery
//! attempts, bounce reports, suppression history) are only ever read.
//! Nothing an admin does can rewrite what happened; the most it can do is
//! supersede it, the same discipline the rest of the schema keeps.

use anyhow::Context;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

// -------------------------------------------------------------- overview

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatusCounts {
    pub status: String,
    pub last_24h: i64,
    pub last_7d: i64,
    pub total: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TenantVolume {
    pub tenant: String,
    pub last_7d: i64,
    pub total: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DailyVolume {
    pub day: String,
    pub sent: i64,
    pub failed: i64,
    pub suppressed: i64,
    pub queued: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Overview {
    pub by_status: Vec<StatusCounts>,
    pub by_tenant: Vec<TenantVolume>,
    /// Last 14 days, oldest first, for the dashboard chart.
    pub by_day: Vec<DailyVolume>,
    /// Messages waiting in the queue right now.
    pub queue_depth: i64,
    /// Of those, how many are due — a large due backlog with a running
    /// worker means the relay is refusing or unreachable.
    pub queue_due: i64,
    pub active_suppressions: i64,
    pub bounces_7d: i64,
    /// Bounce reports the parser could not join to a message. A persistently
    /// rising number means queue ids are not being captured on the way out.
    pub unmatched_bounces: i64,
}

pub async fn overview(pool: &PgPool) -> anyhow::Result<Overview> {
    let by_status = sqlx::query(
        "select status,
                count(*) filter (where created_at > now() - interval '24 hours') as last_24h,
                count(*) filter (where created_at > now() - interval '7 days')  as last_7d,
                count(*) as total
           from message group by status order by status",
    )
    .fetch_all(pool)
    .await
    .context("counting messages by status")?
    .into_iter()
    .map(|r| StatusCounts {
        status: r.get("status"),
        last_24h: r.get("last_24h"),
        last_7d: r.get("last_7d"),
        total: r.get("total"),
    })
    .collect();

    let by_tenant = sqlx::query(
        "select t.name as tenant,
                count(m.id) filter (where m.created_at > now() - interval '7 days') as last_7d,
                count(m.id) as total
           from tenant t left join message m on m.tenant_id = t.id
          group by t.name order by t.name",
    )
    .fetch_all(pool)
    .await
    .context("counting messages by tenant")?
    .into_iter()
    .map(|r| TenantVolume {
        tenant: r.get("tenant"),
        last_7d: r.get("last_7d"),
        total: r.get("total"),
    })
    .collect();

    let by_day = sqlx::query(
        "select to_char(date_trunc('day', created_at), 'YYYY-MM-DD') as day,
                count(*) filter (where status = 'sent')       as sent,
                count(*) filter (where status = 'failed')     as failed,
                count(*) filter (where status = 'suppressed') as suppressed,
                count(*) filter (where status = 'queued')     as queued
           from message
          where created_at > now() - interval '14 days'
          group by 1 order by 1",
    )
    .fetch_all(pool)
    .await
    .context("counting messages by day")?
    .into_iter()
    .map(|r| DailyVolume {
        day: r.get("day"),
        sent: r.get("sent"),
        failed: r.get("failed"),
        suppressed: r.get("suppressed"),
        queued: r.get("queued"),
    })
    .collect();

    let counters = sqlx::query(
        "select
           (select count(*) from message where status = 'queued') as queue_depth,
           (select count(*) from message
             where status = 'queued' and next_attempt_at <= now()) as queue_due,
           (select count(*) from suppression where removed_at is null) as active_suppressions,
           (select count(*) from bounce_report
             where received_at > now() - interval '7 days') as bounces_7d,
           (select count(*) from bounce_report where message_id is null) as unmatched_bounces",
    )
    .fetch_one(pool)
    .await
    .context("loading overview counters")?;

    Ok(Overview {
        by_status,
        by_tenant,
        by_day,
        queue_depth: counters.get("queue_depth"),
        queue_due: counters.get("queue_due"),
        active_suppressions: counters.get("active_suppressions"),
        bounces_7d: counters.get("bounces_7d"),
        unmatched_bounces: counters.get("unmatched_bounces"),
    })
}

// -------------------------------------------------------------- messages

#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageRow {
    pub id: Uuid,
    pub tenant: String,
    pub mail_from: String,
    pub rcpt_to: String,
    pub subject: String,
    pub status: String,
    pub attempts: i32,
    pub relay_queue_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct MessageFilter<'a> {
    pub tenant: Option<&'a str>,
    pub status: Option<&'a str>,
    /// Substring match on the recipient, case-insensitive.
    pub rcpt: Option<&'a str>,
    /// Keyset cursor: strictly older than this row. Both parts together —
    /// `created_at` alone would skip or repeat rows created in the same
    /// microsecond, and OFFSET paging re-scans everything it skips, which
    /// is exactly the slow-after-a-while this exists to prevent.
    pub before: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

pub async fn messages(
    pool: &PgPool,
    filter: &MessageFilter<'_>,
) -> anyhow::Result<Vec<MessageRow>> {
    let (before_at, before_id) = match filter.before {
        Some((at, id)) => (Some(at), Some(id)),
        None => (None, None),
    };
    let rows = sqlx::query(
        "select m.id, t.name as tenant, m.mail_from, m.rcpt_to, m.subject,
                m.status, m.attempts, m.relay_queue_id, m.last_error,
                m.created_at, m.completed_at
           from message m join tenant t on t.id = m.tenant_id
          where ($1::text is null or t.name = $1)
            and ($2::text is null or m.status = $2)
            and ($3::text is null or m.rcpt_to ilike '%' || $3 || '%')
            and ($4::timestamptz is null or (m.created_at, m.id) < ($4, $5))
          order by m.created_at desc, m.id desc
          limit $6",
    )
    .bind(filter.tenant)
    .bind(filter.status)
    .bind(filter.rcpt)
    .bind(before_at)
    .bind(before_id)
    .bind(filter.limit.clamp(1, 201))
    .fetch_all(pool)
    .await
    .context("listing messages")?;

    Ok(rows
        .into_iter()
        .map(|r| MessageRow {
            id: r.get("id"),
            tenant: r.get("tenant"),
            mail_from: r.get("mail_from"),
            rcpt_to: r.get("rcpt_to"),
            subject: r.get("subject"),
            status: r.get("status"),
            attempts: r.get("attempts"),
            relay_queue_id: r.get("relay_queue_id"),
            last_error: r.get("last_error"),
            created_at: r.get("created_at"),
            completed_at: r.get("completed_at"),
        })
        .collect())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttemptRow {
    pub attempt: i32,
    pub outcome: String,
    pub smtp_code: Option<i32>,
    pub relay_queue_id: Option<String>,
    pub detail: Option<String>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BounceRow {
    pub id: i64,
    pub received_at: DateTime<Utc>,
    pub final_rcpt: Option<String>,
    pub status_code: Option<String>,
    pub classification: Option<String>,
    pub diagnostic: Option<String>,
    pub relay_queue_id: Option<String>,
    pub message_id: Option<Uuid>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageDetail {
    #[serde(flatten)]
    pub row: MessageRow,
    pub idempotency_key: String,
    pub from_name: Option<String>,
    pub reply_to: Option<String>,
    /// The text body, when it still exists. Bodies are purged after
    /// BODY_RETENTION_DAYS; `body_purged_at` says when that happened.
    pub body_text: Option<String>,
    pub has_html: bool,
    pub body_purged_at: Option<DateTime<Utc>>,
    pub attachments: Vec<AttachmentMeta>,
    pub delivery_attempts: Vec<AttemptRow>,
    pub bounces: Vec<BounceRow>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachmentMeta {
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub sha256: String,
}

pub async fn message_detail(pool: &PgPool, id: Uuid) -> anyhow::Result<Option<MessageDetail>> {
    let Some(r) = sqlx::query(
        "select m.id, t.name as tenant, m.idempotency_key, m.mail_from,
                m.from_name, m.rcpt_to, m.reply_to, m.subject, m.body_text,
                m.body_html is not null as has_html, m.status, m.attempts,
                m.relay_queue_id, m.last_error, m.created_at, m.completed_at,
                m.body_purged_at
           from message m join tenant t on t.id = m.tenant_id
          where m.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("loading message")?
    else {
        return Ok(None);
    };

    let attachments = sqlx::query(
        "select filename, content_type, length(content) as size,
                encode(sha256, 'hex') as sha256
           from message_attachment where message_id = $1 order by id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .context("loading attachment metadata")?
    .into_iter()
    .map(|a| AttachmentMeta {
        filename: a.get("filename"),
        content_type: a.get("content_type"),
        size: a.get::<i32, _>("size") as i64,
        sha256: a.get("sha256"),
    })
    .collect();

    let delivery_attempts = sqlx::query(
        "select attempt, outcome, smtp_code, relay_queue_id, detail, finished_at
           from delivery_attempt where message_id = $1 order by attempt, id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .context("loading delivery attempts")?
    .into_iter()
    .map(|a| AttemptRow {
        attempt: a.get("attempt"),
        outcome: a.get("outcome"),
        smtp_code: a.get("smtp_code"),
        relay_queue_id: a.get("relay_queue_id"),
        detail: a.get("detail"),
        finished_at: a.get("finished_at"),
    })
    .collect();

    let bounces = sqlx::query(
        "select id, received_at, final_rcpt, status_code, classification,
                diagnostic, relay_queue_id, message_id
           from bounce_report where message_id = $1 order by received_at",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .context("loading bounce reports")?
    .into_iter()
    .map(bounce_row)
    .collect();

    Ok(Some(MessageDetail {
        row: MessageRow {
            id: r.get("id"),
            tenant: r.get("tenant"),
            mail_from: r.get("mail_from"),
            rcpt_to: r.get("rcpt_to"),
            subject: r.get("subject"),
            status: r.get("status"),
            attempts: r.get("attempts"),
            relay_queue_id: r.get("relay_queue_id"),
            last_error: r.get("last_error"),
            created_at: r.get("created_at"),
            completed_at: r.get("completed_at"),
        },
        idempotency_key: r.get("idempotency_key"),
        from_name: r.get("from_name"),
        reply_to: r.get("reply_to"),
        body_text: r.get("body_text"),
        has_html: r.get("has_html"),
        body_purged_at: r.get("body_purged_at"),
        attachments,
        delivery_attempts,
        bounces,
    }))
}

// ----------------------------------------------------------- suppressions

#[derive(Debug, Clone, serde::Serialize)]
pub struct SuppressionRow {
    pub id: i64,
    /// None means global — it applies to every tenant.
    pub tenant: Option<String>,
    pub address: String,
    pub reason: String,
    pub source: String,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
    pub removed_by: Option<String>,
}

/// The whole list across tenants, history included when asked for —
/// "suppressed on the 3rd, lifted on the 9th" is the answer the admin is
/// usually looking for.
///
/// Keyset-paged on the bigserial id (descending id = descending creation
/// time), so page N+10 costs the same as page 1.
pub async fn suppressions(
    pool: &PgPool,
    address: Option<&str>,
    include_removed: bool,
    before_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<SuppressionRow>> {
    let rows = sqlx::query(
        "select s.id, t.name as tenant, s.address, s.reason, s.source,
                s.detail, s.created_at, s.removed_at, s.removed_by
           from suppression s left join tenant t on t.id = s.tenant_id
          where ($1::text is null or s.address ilike '%' || $1 || '%')
            and ($2 or s.removed_at is null)
            and ($3::bigint is null or s.id < $3)
          order by s.id desc
          limit $4",
    )
    .bind(address)
    .bind(include_removed)
    .bind(before_id)
    .bind(limit.clamp(1, 201))
    .fetch_all(pool)
    .await
    .context("listing suppressions")?;

    Ok(rows
        .into_iter()
        .map(|r| SuppressionRow {
            id: r.get("id"),
            tenant: r.get("tenant"),
            address: r.get("address"),
            reason: r.get("reason"),
            source: r.get("source"),
            detail: r.get("detail"),
            created_at: r.get("created_at"),
            removed_at: r.get("removed_at"),
            removed_by: r.get("removed_by"),
        })
        .collect())
}

// ---------------------------------------------------------------- bounces

fn bounce_row(r: sqlx::postgres::PgRow) -> BounceRow {
    BounceRow {
        id: r.get("id"),
        received_at: r.get("received_at"),
        final_rcpt: r.get("final_rcpt"),
        status_code: r.get("status_code"),
        classification: r.get("classification"),
        diagnostic: r.get("diagnostic"),
        relay_queue_id: r.get("relay_queue_id"),
        message_id: r.get("message_id"),
    }
}

/// Keyset-paged on the bigserial id, newest first.
pub async fn bounces(
    pool: &PgPool,
    before_id: Option<i64>,
    limit: i64,
) -> anyhow::Result<Vec<BounceRow>> {
    let rows = sqlx::query(
        "select id, received_at, final_rcpt, status_code, classification,
                diagnostic, relay_queue_id, message_id
           from bounce_report
          where ($1::bigint is null or id < $1)
          order by id desc
          limit $2",
    )
    .bind(before_id)
    .bind(limit.clamp(1, 201))
    .fetch_all(pool)
    .await
    .context("listing bounces")?;

    Ok(rows.into_iter().map(bounce_row).collect())
}

/// The raw DSN of one bounce, for the unparsed-bounce debugging loop.
pub async fn bounce_raw(pool: &PgPool, id: i64) -> anyhow::Result<Option<String>> {
    let row = sqlx::query("select raw from bounce_report where id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("loading raw bounce")?;
    Ok(row.map(|r| r.get("raw")))
}
